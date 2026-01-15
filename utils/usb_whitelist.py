import json
import os
from pathlib import Path

class USBWhitelist:
    def __init__(self):
        self.whitelist_file = Path("config/usb_whitelist.json")
        self.blocklist_file = Path("config/usb_blocklist.json")
        
        # Ensure config directory exists with proper permissions
        config_dir = Path("config")
        if not config_dir.exists():
            config_dir.mkdir(parents=True, exist_ok=True)
            
        self.whitelist = self._load_whitelist()
        self.blocklist = self._load_blocklist()
        
        # Debug print
        print(f"Loaded whitelist: {self.whitelist}")
        print(f"Loaded blocklist: {self.blocklist}")

    def _load_whitelist(self):
        """Load the whitelist from JSON file"""
        if not self.whitelist_file.exists():
            self.whitelist_file.parent.mkdir(parents=True, exist_ok=True)
            return {}
        
        try:
            with open(self.whitelist_file, 'r') as f:
                return json.load(f)
        except:
            return {}

    def _load_blocklist(self):
        """Load the blocklist from JSON file"""
        if not self.blocklist_file.exists():
            self.blocklist_file.parent.mkdir(parents=True, exist_ok=True)
            return {}
        
        try:
            with open(self.blocklist_file, 'r') as f:
                return json.load(f)
        except:
            return {}

    def save_whitelist(self):
        """Save the whitelist to JSON file"""
        self.whitelist_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.whitelist_file, 'w') as f:
            json.dump(self.whitelist, f, indent=4)

    def save_blocklist(self):
        """Save the blocklist to JSON file"""
        self.blocklist_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.blocklist_file, 'w') as f:
            json.dump(self.blocklist, f, indent=4)

    def is_device_allowed(self, vendor_id, product_id):
        """Check if a device is in the whitelist"""
        device_id = f"{vendor_id:04x}:{product_id:04x}"
        return device_id in self.whitelist

    def is_device_blocked(self, vendor_id, product_id):
        """Check if a device is in the blocklist"""
        device_id = f"{vendor_id:04x}:{product_id:04x}"
        return device_id in self.blocklist

    def add_device(self, vendor_id, product_id, name):
        """Add a device to the whitelist and remove from blocklist if present"""
        device_id = f"{vendor_id:04x}:{product_id:04x}"
        self.whitelist[device_id] = {
            "name": name,
            "vendor_id": vendor_id,
            "product_id": product_id
        }
        # Remove from blocklist if present
        if device_id in self.blocklist:
            del self.blocklist[device_id]
            self.save_blocklist()
        self.save_whitelist()

    def block_device(self, vendor_id, product_id, name):
        """Add a device to the blocklist"""
        device_id = f"{vendor_id:04x}:{product_id:04x}"
        self.blocklist[device_id] = {
            "name": name,
            "vendor_id": vendor_id,
            "product_id": product_id
        }
        self.save_blocklist()

    def remove_device(self, vendor_id, product_id):
        """Remove a device from the whitelist"""
        device_id = f"{vendor_id:04x}:{product_id:04x}"
        if device_id in self.whitelist:
            del self.whitelist[device_id]
            self.save_whitelist()

    def unblock_device(self, vendor_id, product_id):
        """Remove a device from the blocklist"""
        device_id = f"{vendor_id:04x}:{product_id:04x}"
        if device_id in self.blocklist:
            # First get the device details
            device = self.blocklist[device_id]
            
            # Remove from blocklist
            del self.blocklist[device_id]
            
            # Save blocklist immediately to ensure changes are persisted
            self.save_blocklist()
            print(f"Device {device_id} removed from blocklist")
            
            # Now add to whitelist (which also saves the whitelist)
            self.add_device(vendor_id, product_id, device['name'])
        
        # Even if not in blocklist, we should make sure it's allowed
        else:
            print(f"Device {device_id} not found in blocklist") 