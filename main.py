import os
import time
import subprocess
from plyer import notification

def scan_network():
    try:
        result = subprocess.run(["sudo", "arp-scan", "-l"], capture_output=True, text=True)
        lines = result.stdout.split("\n")
        devices = set()

        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 2:
                mac_address = parts[1].strip()
                devices.add(mac_address)

        return devices
    except Exception as e:
        print(f"Error scanning network: {e}")
        return set()

known_devices = scan_network()
print("Monitoring network for new devices...")

while True:
    current_devices = scan_network()
    new_devices = current_devices - known_devices

    if new_devices:
        for device in new_devices:
            print(f"New device detected: {device}")
            notification.notify(
                title="New Device Connected!",
                message=f"MAC Address: {device}",
                timeout=5
            )

        known_devices.update(new_devices)

    time.sleep(10)  # Adjust scanning frequency
