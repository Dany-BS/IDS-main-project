import customtkinter as ctk
from tkinter import messagebox
import wmi
import os
import sys
import subprocess
import platform

# Update import to use absolute path
from utils.usb_whitelist import USBWhitelist

class ExternalDeviceWindow(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.whitelist = USBWhitelist()
        self.known_devices = set()  # Track currently known devices
        self.wmi = wmi.WMI()
        self.setup_ui()
        # Update devices every 2 seconds
        self.after(2000, self.periodic_update)

    def setup_ui(self):
        # Create main container
        main_container = ctk.CTkFrame(self)
        main_container.pack(fill="both", expand=True, padx=20, pady=20)

        # Add back button at the top
        back_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        back_frame.pack(fill="x", pady=(0, 10))
        
        back_btn = ctk.CTkButton(
            back_frame,
            text="↩️ Back",
            command=self.master.go_back,
            width=100,
            fg_color="transparent",
            text_color=("gray10", "gray90"),
            hover_color=("gray70", "gray30")
        )
        back_btn.pack(side="left")

        # Add Manage Whitelist button
        whitelist_btn = ctk.CTkButton(
            back_frame,
            text="⚙️ Manage Whitelist",
            command=self.show_whitelist_manager,
            width=150
        )
        whitelist_btn.pack(side="right")

        # Title
        ctk.CTkLabel(
            main_container,
            text="🔌 USB Intrusion Detection",
            font=("Helvetica", 24, "bold")
        ).pack(pady=10)

        # Device List Frame
        devices_frame = ctk.CTkFrame(main_container)
        devices_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Headers with fixed widths
        headers_frame = ctk.CTkFrame(devices_frame)
        headers_frame.pack(fill="x", padx=10, pady=5)
        
        # Define column widths
        name_width = 40
        id_width = 15
        status_width = 15

        # Add headers with fixed widths
        ctk.CTkLabel(
            headers_frame,
            text="Device Name",
            font=("Helvetica", 12, "bold"),
            width=name_width*8  # Multiply by character width
        ).pack(side="left")
        
        ctk.CTkLabel(
            headers_frame,
            text="Vendor ID",
            font=("Helvetica", 12, "bold"),
            width=id_width*8
        ).pack(side="left")

        ctk.CTkLabel(
            headers_frame,
            text="Product ID",
            font=("Helvetica", 12, "bold"),
            width=id_width*8
        ).pack(side="left")
        
        ctk.CTkLabel(
            headers_frame,
            text="Status",
            font=("Helvetica", 12, "bold"),
            width=status_width*8
        ).pack(side="left")

        # Devices list
        self.devices_list = ctk.CTkTextbox(devices_frame, font=("Courier", 12))
        self.devices_list.pack(fill="both", expand=True, padx=10, pady=5)

        # Notification area
        self.notification_area = ctk.CTkTextbox(main_container, height=100)
        self.notification_area.pack(fill="x", padx=20, pady=10)

        # Show initial devices
        self.update_device_list()

    def get_connected_devices(self):
        devices = []
        try:
            # Get removable drives (USB flash drives, external HDDs, phones)
            for disk in self.wmi.Win32_LogicalDisk(DriveType=2):  # Type 2 = Removable disk
                try:
                    # Get the associated physical drive
                    for partition in self.wmi.Win32_DiskDriveToDiskPartition():
                        if partition.Dependent.DeviceID == disk.DeviceID:
                            drive = self.wmi.Win32_DiskDrive(DeviceID=partition.Antecedent.DeviceID)[0]
                            if drive.InterfaceType == "USB":
                                device_id = drive.PNPDeviceID
                                if 'VID_' in device_id and 'PID_' in device_id:
                                    vid = int(device_id.split('VID_')[1][:4], 16)
                                    pid = int(device_id.split('PID_')[1][:4], 16)
                                    
                                    name = f"{disk.VolumeName or 'USB Drive'} ({disk.DeviceID})"
                                    manufacturer = getattr(drive, 'Manufacturer', 'Unknown')
                                    
                                    devices.append({
                                        'name': f"{manufacturer} {name}".strip(),
                                        'vendor_id': vid,
                                        'product_id': pid,
                                        'allowed': self.whitelist.is_device_allowed(vid, pid)
                                    })
                except:
                    continue

            # Get other external USB devices (like phones without mounted storage)
            for usb_device in self.wmi.Win32_PnPEntity():
                try:
                    device_id = usb_device.DeviceID or ""
                    if not ("USB" in device_id and "VID_" in device_id and "PID_" in device_id):
                        continue

                    # Get device name and check if it's a likely external device
                    name = getattr(usb_device, 'Name', '')
                    if not name:
                        continue

                    # Skip internal and system devices
                    if any(x.lower() in name.lower() for x in [
                        'hub', 'root', 'composite', 'controller', 
                        'keyboard', 'mouse', 'system', 'volume',
                        'port', 'intel', 'amd', 'nvidia', 'realtek',
                        'camera', 'mic', 'audio', 'finger', 'print',
                        'sensor', 'touchpad', 'bluetooth'
                    ]):
                        continue

                    # Get vendor and product IDs
                    vid = int(device_id.split('VID_')[1][:4], 16)
                    pid = int(device_id.split('PID_')[1][:4], 16)
                    
                    # Skip if already added
                    if any(d['vendor_id'] == vid and d['product_id'] == pid for d in devices):
                        continue

                    manufacturer = getattr(usb_device, 'Manufacturer', 'Unknown Manufacturer')
                    
                    devices.append({
                        'name': f"{manufacturer} {name}".strip(),
                        'vendor_id': vid,
                        'product_id': pid,
                        'allowed': self.whitelist.is_device_allowed(vid, pid)
                    })
                except:
                    continue

        except Exception as e:
            self.log_message(f"Error detecting devices: {str(e)}")

        return devices

    def update_device_list(self):
        try:
            devices = self.get_connected_devices()
            current_devices = {(d['vendor_id'], d['product_id']) for d in devices}
            
            # Check for new or removed+reconnected devices
            for device in devices:
                device_key = (device['vendor_id'], device['product_id'])
                if (device_key not in self.known_devices or 
                    (not self.whitelist.is_device_allowed(device['vendor_id'], device['product_id']) and
                     not self.whitelist.is_device_blocked(device['vendor_id'], device['product_id']))):
                    self.handle_new_device(device)

            # Update known devices
            self.known_devices = current_devices
            
            # Update display
            self.devices_list.delete("1.0", "end")
            if not devices:
                self.devices_list.insert("end", "No USB devices currently connected\n")
                return

            # Format string for aligned columns
            format_str = "{:<40} {:<15} {:<15} {:<15}\n"

            for device in devices:
                # Truncate name if too long
                name = device['name'][:37] + "..." if len(device['name']) > 37 else device['name']
                
                if self.whitelist.is_device_allowed(device['vendor_id'], device['product_id']):
                    status = "✅ Allowed"
                    self.devices_list.insert("end", format_str.format(
                        name,
                        f"{device['vendor_id']:04x}",
                        f"{device['product_id']:04x}",
                        status
                    ))
                elif self.whitelist.is_device_blocked(device['vendor_id'], device['product_id']):
                    status = "❌ Blocked"
                    self.devices_list.insert("end", format_str.format(
                        name,
                        f"{device['vendor_id']:04x}",
                        f"{device['product_id']:04x}",
                        status
                    ))
                    # Ensure blocked devices stay ejected
                    self.eject_device(device)
                else:
                    # Device is neither in whitelist nor blocklist, prompt for permission
                    self.handle_new_device(device)

        except Exception as e:
            self.log_message(f"Error updating device list: {str(e)}")

    def handle_new_device(self, device):
        """Handle detection of a new USB device"""
        # Check if we've already handled this device recently
        device_key = (device['vendor_id'], device['product_id'])
        
        message = f"New USB device detected:\n{device['name']}\nVendor ID: {device['vendor_id']:04x}\nProduct ID: {device['product_id']:04x}"
        self.log_message(f"⚠️ {message}")
        
        print(f"New device detected: {device}")
        
        if messagebox.askyesno("New USB Device", f"{message}\n\nDo you want to allow this device?"):
            self.whitelist.add_device(device['vendor_id'], device['product_id'], device['name'])
            self.log_message(f"✅ Device {device['name']} has been whitelisted")
            print(f"Device added to whitelist: {device}")
            
            # Re-enable the device if it was previously disabled
            try:
                cmd = f'wmic path Win32_PnPEntity where "DeviceID like \'%VID_{device["vendor_id"]:04x}%\' and DeviceID like \'%PID_{device["product_id"]:04x}%\'" get DeviceID'
                output = subprocess.check_output(cmd, shell=True, text=True).strip()
                device_paths = output.split('\n')[1:]  # Skip header
                
                for device_path in device_paths:
                    if device_path.strip():
                        enable_cmd = f'pnputil /enable-device "{device_path.strip()}"'
                        subprocess.run(enable_cmd, shell=True, check=True,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                self.log_message(f"Warning: Could not enable device: {str(e)}")
                
            return True
        else:
            self.whitelist.block_device(device['vendor_id'], device['product_id'], device['name'])
            self.log_message(f"❌ Device {device['name']} has been blocked")
            print(f"Device added to blocklist: {device}")
            # Immediately eject the device
            self.eject_device(device)
            return False

    def eject_device(self, device):
        """Eject a USB device"""
        try:
            # Get all logical disks for USB devices
            if platform.system() == "Windows":
                # First try to eject any associated drives
                cmd = 'wmic logicaldisk where "DriveType=2" get DeviceID, PNPDeviceID'
                output = subprocess.check_output(cmd, shell=True, text=True).strip()
                
                device_ejected = False
                # Parse the output to find matching device
                lines = output.split('\n')[1:]  # Skip header
                for line in lines:
                    parts = line.strip().split()
                    if not parts:
                        continue
                        
                    drive_letter = parts[0]
                    device_id = ' '.join(parts[1:]) if len(parts) > 1 else ''
                    
                    # Check if this is our target device
                    if (f"VID_{device['vendor_id']:04x}" in device_id.upper() and 
                        f"PID_{device['product_id']:04x}" in device_id.upper()):
                        # Eject the drive
                        eject_cmd = f'powershell "$driveEject = New-Object -comObject Shell.Application; $driveEject.Namespace(17).ParseName(\'{drive_letter}\').InvokeVerb(\'Eject\')"'
                        subprocess.run(eject_cmd, shell=True, check=True)
                        self.log_message(f"📤 Device {device['name']} has been ejected")
                        device_ejected = True

                # Then disable the device using device instance path
                try:
                    # Get device instance path
                    cmd = f'wmic path Win32_PnPEntity where "DeviceID like \'%VID_{device["vendor_id"]:04x}%\' and DeviceID like \'%PID_{device["product_id"]:04x}%\'" get DeviceID'
                    output = subprocess.check_output(cmd, shell=True, text=True).strip()
                    device_paths = output.split('\n')[1:]  # Skip header
                    
                    for device_path in device_paths:
                        if device_path.strip():
                            disable_cmd = f'pnputil /disable-device "{device_path.strip()}"'
                            subprocess.run(disable_cmd, shell=True, check=True,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            self.log_message(f"🚫 Device {device['name']} has been disabled")
                            device_ejected = True

                except Exception as e:
                    self.log_message(f"Warning: Could not disable device: {str(e)}")

                if not device_ejected:
                    self.log_message(f"⚠️ Could not find matching drive for {device['name']}")

            else:  # Linux
                # Get device path
                cmd = "lsusb"
                output = subprocess.check_output(cmd, shell=True, text=True)
                for line in output.split('\n'):
                    if (f"{device['vendor_id']:04x}" in line.lower() and 
                        f"{device['product_id']:04x}" in line.lower()):
                        bus = line.split()[1]
                        dev = line.split()[3].rstrip(':')
                        path = f"/dev/bus/usb/{bus}/{dev}"
                        
                        # Unmount and power off
                        subprocess.run(['udisksctl', 'unmount', '-b', path], check=True)
                        subprocess.run(['udisksctl', 'power-off', '-b', path], check=True)
                        self.log_message(f"📤 Device {device['name']} has been ejected")
                        return

            self.log_message(f"⚠️ Could not find matching drive for {device['name']}")

        except subprocess.CalledProcessError as e:
            self.log_message(f"❌ Failed to eject device: {str(e)}")
        except Exception as e:
            self.log_message(f"❌ Error during device ejection: {str(e)}")

    def show_whitelist_manager(self):
        """Show the whitelist management window"""
        dialog = WhitelistManager(self)
        dialog.grab_set()

    def log_message(self, message):
        """Add a message to the notification area"""
        self.notification_area.insert("1.0", f"{message}\n")

    def periodic_update(self):
        """Update the device list every 2 seconds"""
        self.update_device_list()
        self.after(2000, self.periodic_update) 

class WhitelistManager(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Device Management")
        self.geometry("600x700")
        
        # Create notebook for tabs
        self.notebook = ctk.CTkTabview(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add tabs
        self.notebook.add("Allowed Devices")
        self.notebook.add("Blocked Devices")
        
        # Allowed devices tab
        allowed_frame = self.notebook.tab("Allowed Devices")
        ctk.CTkLabel(
            allowed_frame,
            text="Whitelisted Devices",
            font=("Helvetica", 16, "bold")
        ).pack(pady=10)
        
        # Create scrollable frame for allowed devices
        self.allowed_frame = ctk.CTkScrollableFrame(allowed_frame)
        self.allowed_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        allowed_buttons = ctk.CTkFrame(allowed_frame)
        allowed_buttons.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkButton(
            allowed_buttons,
            text="➕ Add Device",
            command=self.show_add_device_dialog,
            width=150
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            allowed_buttons,
            text="➖ Remove Device",
            command=self.show_remove_device_dialog,
            width=150
        ).pack(side="right", padx=5)
        
        # Blocked devices tab
        blocked_frame = self.notebook.tab("Blocked Devices")
        ctk.CTkLabel(
            blocked_frame,
            text="Blocked Devices",
            font=("Helvetica", 16, "bold")
        ).pack(pady=10)
        
        # Create scrollable frame for blocked devices
        self.blocked_frame = ctk.CTkScrollableFrame(blocked_frame)
        self.blocked_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Update lists
        self.update_devices_list()

    def update_devices_list(self):
        """Update both allowed and blocked devices lists"""
        # Clear existing frames
        for widget in self.allowed_frame.winfo_children():
            widget.destroy()
        for widget in self.blocked_frame.winfo_children():
            widget.destroy()
        
        # Update allowed devices
        if not self.parent.whitelist.whitelist:
            ctk.CTkLabel(
                self.allowed_frame,
                text="No allowed devices"
            ).pack(pady=10)
        else:
            for device_id, device in self.parent.whitelist.whitelist.items():
                device_frame = ctk.CTkFrame(self.allowed_frame)
                device_frame.pack(fill="x", padx=5, pady=5)
                
                # Device info
                info_text = (
                    f"Device: {device['name']}\n"
                    f"Vendor ID: {device['vendor_id']:04x}\n"
                    f"Product ID: {device['product_id']:04x}"
                )
                ctk.CTkLabel(
                    device_frame,
                    text=info_text,
                    justify="left"
                ).pack(side="left", padx=10, pady=5)
                
                # Remove button
                ctk.CTkButton(
                    device_frame,
                    text="Remove",
                    command=lambda d=device: self.remove_device(d),
                    width=80
                ).pack(side="right", padx=10, pady=5)
        
        # Update blocked devices
        if not self.parent.whitelist.blocklist:
            ctk.CTkLabel(
                self.blocked_frame,
                text="No blocked devices"
            ).pack(pady=10)
        else:
            for device_id, device in self.parent.whitelist.blocklist.items():
                device_frame = ctk.CTkFrame(self.blocked_frame)
                device_frame.pack(fill="x", padx=5, pady=5)
                
                # Device info
                info_text = (
                    f"Device: {device['name']}\n"
                    f"Vendor ID: {device['vendor_id']:04x}\n"
                    f"Product ID: {device['product_id']:04x}"
                )
                ctk.CTkLabel(
                    device_frame,
                    text=info_text,
                    justify="left"
                ).pack(side="left", padx=10, pady=5)
                
                # Unblock button
                ctk.CTkButton(
                    device_frame,
                    text="Unblock",
                    command=lambda d=device: self.unblock_device(d),
                    width=80
                ).pack(side="right", padx=10, pady=5)

    def remove_device(self, device):
        """Remove a device from whitelist"""
        if messagebox.askyesno("Remove Device", 
            f"Are you sure you want to remove {device['name']} from allowed devices?"):
            self.parent.whitelist.remove_device(device['vendor_id'], device['product_id'])
            
            # Remove from known devices to force re-prompt
            device_key = (device['vendor_id'], device['product_id'])
            if device_key in self.parent.known_devices:
                self.parent.known_devices.remove(device_key)
            
            self.update_devices_list()
            self.parent.log_message(f"❌ Device {device['name']} removed from whitelist")
            
            # If device is currently connected, prompt for permission again
            for connected_device in self.parent.get_connected_devices():
                if (connected_device['vendor_id'] == device['vendor_id'] and 
                    connected_device['product_id'] == device['product_id']):
                    self.parent.handle_new_device(connected_device)
                    break

    def unblock_device(self, device):
        """Unblock a device and enable it"""
        if messagebox.askyesno("Unblock Device", 
            f"Are you sure you want to unblock {device['name']}?"):
            try:
                # Remove from blocklist first, add to whitelist if needed
                # This is the most important step and should be done first
                self.parent.whitelist.unblock_device(device['vendor_id'], device['product_id'])
                
                # Add to whitelist explicitly to ensure it's allowed
                self.parent.whitelist.add_device(device['vendor_id'], device['product_id'], device['name'])
                
                # Add to known_devices to prevent any re-prompting
                device_key = (device['vendor_id'], device['product_id'])
                self.parent.known_devices.add(device_key)
                
                # Log the change
                self.parent.log_message(f"✅ Device {device['name']} has been unblocked and added to whitelist")
                
                # Update UI immediately to reflect the change
                self.update_devices_list()
                
                # Try to enable hardware with a slight delay to ensure whitelist is saved
                self.after(200, lambda: self.try_enable_device(device))
                
            except Exception as e:
                # Log the specific error
                error_msg = f"Error unblocking device: {str(e)}"
                print(error_msg)
                self.parent.log_message(error_msg)
                messagebox.showerror("Error", error_msg)
    
    def try_enable_device(self, device):
        """Try to re-enable a device after it has been unblocked in the whitelist"""
        try:
            # Get device instance paths for the device
            vendor_id_hex = f"{device['vendor_id']:04x}"
            product_id_hex = f"{device['product_id']:04x}"
            device_id = f"{vendor_id_hex}&{product_id_hex}"
            
            # Lookup device in device manager
            import wmi
            c = wmi.WMI()
            
            # Log that we're trying to enable the device
            self.parent.log_message(f"Attempting to enable hardware for {device['name']} (VID_PID: {device_id})")
            
            # Track if we successfully enabled the device
            enabled = False
            error_details = []
            
            # METHOD 1: Try using WMI
            try:
                print(f"Looking for device with hardware id *VID_{vendor_id_hex}&PID_{product_id_hex}*")
                # Search for devices with matching hardware ID (case insensitive)
                usb_devices = c.Win32_PnPEntity()
                for usb_device in usb_devices:
                    # Check hardware IDs if available
                    if hasattr(usb_device, 'HardwareID') and usb_device.HardwareID:
                        for hw_id in usb_device.HardwareID:
                            # Case insensitive compare
                            if f"VID_{vendor_id_hex}&PID_{product_id_hex}".lower() in hw_id.lower():
                                print(f"Found matching device: {usb_device.Name}")
                                print(f"Device status: {usb_device.Status}")
                                
                                if usb_device.Status == "Error":
                                    # Try to enable via Windows API
                                    result = usb_device.Enable()
                                    if result[0] == 0:  # 0 means success
                                        enabled = True
                                        self.parent.log_message(f"✅ Successfully enabled device via WMI")
                                    else:
                                        error_details.append(f"WMI enable failed with code {result[0]}")
                                else:
                                    self.parent.log_message(f"Device already enabled or in status: {usb_device.Status}")
                                    enabled = True  # Consider it enabled if not in error state
                                break
            except Exception as wmi_ex:
                error_details.append(f"WMI method failed: {str(wmi_ex)}")
                print(f"WMI method failed: {str(wmi_ex)}")
            
            # METHOD 2: Try using devcon if WMI failed
            if not enabled:
                try:
                    import subprocess
                    import os
                    
                    # Use devcon to enable the device
                    self.parent.log_message("Trying devcon to enable the device...")
                    
                    # Create the hardware ID pattern for devcon
                    hw_pattern = f"*VID_{vendor_id_hex}&PID_{product_id_hex}*"
                    
                    # Run devcon to enable the device
                    result = subprocess.run(
                        ['devcon', 'enable', hw_pattern], 
                        capture_output=True, 
                        text=True
                    )
                    
                    if "No matching devices found" not in result.stdout and "No devices disabled" not in result.stdout:
                        enabled = True
                        self.parent.log_message(f"✅ Successfully enabled device via devcon")
                    else:
                        error_details.append(f"Devcon couldn't find matching device: {result.stdout}")
                except Exception as devcon_ex:
                    error_details.append(f"Devcon method failed: {str(devcon_ex)}")
                    print(f"Devcon method failed: {str(devcon_ex)}")
            
            # METHOD 3: Try using pnputil as a last resort
            if not enabled:
                try:
                    import subprocess
                    
                    # Use pnputil to list and enable all disabled devices (sledgehammer approach)
                    self.parent.log_message("Trying pnputil as final attempt...")
                    
                    # Run pnputil to list all devices
                    result = subprocess.run(
                        ['pnputil', '/enum-devices', '/disabled'], 
                        capture_output=True, 
                        text=True
                    )
                    
                    # Check if there are any disabled devices
                    if "Instance ID:" in result.stdout:
                        # Enable each disabled device
                        for line in result.stdout.splitlines():
                            if "Instance ID:" in line:
                                instance_id = line.split(':', 1)[1].strip()
                                
                                # Check if this device matches our VID/PID
                                if f"vid_{vendor_id_hex}&pid_{product_id_hex}".lower() in instance_id.lower():
                                    enable_cmd = ['pnputil', '/enable-device', instance_id]
                                    enable_result = subprocess.run(
                                        enable_cmd,
                                        capture_output=True,
                                        text=True
                                    )
                                    
                                    if "successfully enabled" in enable_result.stdout.lower():
                                        enabled = True
                                        self.parent.log_message(f"✅ Successfully enabled device via pnputil")
                                    else:
                                        error_details.append(f"Pnputil enable failed: {enable_result.stdout}")
                    else:
                        self.parent.log_message("No disabled devices found with pnputil")
                except Exception as pnp_ex:
                    error_details.append(f"Pnputil method failed: {str(pnp_ex)}")
                    print(f"Pnputil method failed: {str(pnp_ex)}")
            
            # FINALLY: Trigger a device rescan to help Windows re-enumerate devices
            try:
                import subprocess
                
                # Try both methods to maximize chance of success
                self.parent.log_message("Triggering device rescan...")
                
                # Method 1: Powershell SendKeys approach
                subprocess.run(
                    ['powershell', '-Command', "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); [System.Windows.Forms.SendKeys]::SendWait('^');"],
                    capture_output=True
                )
                
                # Method 2: Devcon rescan approach
                subprocess.run(
                    ['devcon', 'rescan'],
                    capture_output=True
                )
                
                self.parent.log_message("Device rescan complete")
            except Exception as rescan_ex:
                print(f"Device rescan failed: {str(rescan_ex)}")
                # Non-critical, don't add to error details
            
            # Final feedback to user
            if enabled:
                messagebox.showinfo("Success", f"Device '{device['name']}' has been unblocked and enabled successfully.")
            else:
                # Show specific error info but indicate unblocking was successful
                error_text = "\n".join(error_details)
                messagebox.showinfo("Partial Success", 
                    f"Device '{device['name']}' has been unblocked, but could not be automatically enabled.\n\n"
                    f"You may need to disconnect and reconnect the device.\n\n"
                    f"Technical details:\n{error_text}")
                self.parent.log_message(f"Could not automatically enable device hardware. Error details: {error_text}")
                
        except Exception as e:
            error_msg = f"Error enabling device hardware: {str(e)}"
            print(error_msg)
            self.parent.log_message(error_msg)
            # Show message but don't show as error since the device IS unblocked
            messagebox.showinfo("Device Unblocked", 
                f"Device '{device['name']}' has been unblocked, but could not be automatically enabled.\n\n"
                f"You may need to disconnect and reconnect the device for it to work.")

    def show_add_device_dialog(self):
        """Show dialog to add a device"""
        dialog = AddDeviceDialog(self)
        dialog.grab_set()

    def show_remove_device_dialog(self):
        """Show dialog to remove a device"""
        dialog = RemoveDeviceDialog(self)
        dialog.grab_set()

class AddDeviceDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Add Device to Whitelist")
        self.geometry("300x250")

        # Create input fields
        ctk.CTkLabel(self, text="Device Name:").pack(pady=5)
        self.name_entry = ctk.CTkEntry(self)
        self.name_entry.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(self, text="Vendor ID (hex):").pack(pady=5)
        self.vendor_entry = ctk.CTkEntry(self)
        self.vendor_entry.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(self, text="Product ID (hex):").pack(pady=5)
        self.product_entry = ctk.CTkEntry(self)
        self.product_entry.pack(fill="x", padx=20, pady=5)

        # Add button
        ctk.CTkButton(
            self,
            text="Add to Whitelist",
            command=self.add_device
        ).pack(pady=20)

    def add_device(self):
        try:
            name = self.name_entry.get().strip()
            vendor_id = int(self.vendor_entry.get().strip(), 16)
            product_id = int(self.product_entry.get().strip(), 16)

            if not name:
                messagebox.showerror("Error", "Please enter a device name")
                return

            self.parent.parent.whitelist.add_device(vendor_id, product_id, name)
            self.parent.update_devices_list()
            self.parent.parent.log_message(f"✅ Device {name} manually added to whitelist")
            self.destroy()

        except ValueError:
            messagebox.showerror(
                "Error",
                "Invalid ID format. Please enter hex values (e.g., 0483)"
            )

class RemoveDeviceDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Remove Device from Whitelist")
        self.geometry("300x400")

        ctk.CTkLabel(
            self,
            text="Select Device to Remove:",
            font=("Helvetica", 12, "bold")
        ).pack(pady=10)

        # Create device selection frame
        self.selection_frame = ctk.CTkScrollableFrame(self)
        self.selection_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Add devices to selection
        self.selected_device = None
        self.radio_vars = ctk.StringVar()
        
        for device_id, device in self.parent.parent.whitelist.whitelist.items():
            radio = ctk.CTkRadioButton(
                self.selection_frame,
                text=f"{device['name']} ({device_id})",
                variable=self.radio_vars,
                value=device_id
            )
            radio.pack(pady=5, anchor="w")

        # Remove button
        ctk.CTkButton(
            self,
            text="Remove Selected Device",
            command=self.remove_device
        ).pack(pady=20)

    def remove_device(self):
        device_id = self.radio_vars.get()
        if not device_id:
            messagebox.showerror("Error", "Please select a device to remove")
            return

        try:
            device = self.parent.parent.whitelist.whitelist[device_id]
            vid, pid = map(lambda x: int(x, 16), device_id.split(':'))
            
            # Remove from whitelist
            self.parent.parent.whitelist.remove_device(vid, pid)
            
            # Remove from known devices to force re-prompt
            device_key = (vid, pid)
            if device_key in self.parent.parent.known_devices:
                self.parent.parent.known_devices.remove(device_key)
            
            self.parent.update_devices_list()
            self.parent.parent.log_message(f"❌ Device {device['name']} removed from whitelist")
            
            # If device is currently connected, prompt for permission again
            for connected_device in self.parent.parent.get_connected_devices():
                if connected_device['vendor_id'] == vid and connected_device['product_id'] == pid:
                    self.parent.parent.handle_new_device(connected_device)
                    break
                    
            self.destroy()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove device: {str(e)}") 