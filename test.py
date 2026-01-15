import wmi
import ctypes
import time

# Dictionary to store user responses (so the pop-up appears only once per device)
device_permissions = {}

def disable_device(device_id):
    """Disable the device using Windows Device Manager"""
    command = f'pnputil /disable-device "{device_id}"'
    ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f"/c {command}", None, 1)

def enable_device(device_id):
    """Enable the device using Windows Device Manager"""
    command = f'pnputil /enable-device "{device_id}"'
    ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f"/c {command}", None, 1)

def ask_permission(device_name, device_id):
    """Ask user permission only once per device"""
    if device_id in device_permissions:
        if device_permissions[device_id] == "denied":
            print(f"Device '{device_name}' remains blocked.")
            disable_device(device_id)
        return  # Skip pop-up if permission was already given or denied

    response = ctypes.windll.user32.MessageBoxW(None, 
        f"New device detected:\n\n{device_name}\n\nDo you want to allow access?", 
        "Device Permission", 1)  # 1 = OK/Cancel

    if response == 1:  # OK
        print(f"Device '{device_name}' allowed.")
        device_permissions[device_id] = "allowed"
        enable_device(device_id)
    else:  # Cancel
        print(f"Device '{device_name}' blocked.")
        device_permissions[device_id] = "denied"
        disable_device(device_id)

def monitor_external_devices():
    c = wmi.WMI()
    watcher = c.Win32_PnPEntity.watch_for("creation")

    print("Monitoring for external device connections. Press Ctrl+C to exit.")
    try:
        while True:
            device = watcher()
            print(f"New Device Connected: {device.Caption} (Device ID: {device.DeviceID})")
            
            # Ask user permission only once per device
            ask_permission(device.Caption, device.DeviceID)
    
    except KeyboardInterrupt:
        print("Monitoring stopped.")

if __name__ == "__main__":
    monitor_external_devices()
