#!/usr/bin/env python3

import time
import subprocess
import logging
import argparse
import json
import os
from datetime import datetime
from plyer import notification
import platform
import socket
from colorama import init, Fore, Style

# Initialize colorama for Windows color support
init()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_monitor.log"),
        logging.StreamHandler()
    ]
)

class NetworkMonitor:
    def __init__(self, config_file="known_devices.json", scan_interval=30, 
                 notification_timeout=10):
        self.config_file = config_file
        self.scan_interval = scan_interval
        self.notification_timeout = notification_timeout
        self.known_devices = self.load_known_devices()
        self.device_names = {}  # For storing friendly names

    def load_known_devices(self):
        """Load known devices from config file if it exists."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.device_names = data.get("names", {})
                    return set(data.get("devices", []))
            except Exception as e:
                logging.error(f"Error loading known devices: {e}")
        return set()

    def save_known_devices(self):
        """Save known devices to config file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump({
                    "devices": list(self.known_devices),
                    "names": self.device_names,
                    "last_updated": datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving known devices: {e}")

    def get_os_info(self, ip_address):
        """Get OS information for a device using nmap."""
        try:
            # Check if nmap is available
            result = subprocess.run(
                ["nmap", "-O", "-T4", "--osscan-guess", ip_address],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return "OS detection failed"
                
            output = result.stdout
            
            # Try to find OS information in nmap output
            os_info = "Unknown"
            for line in output.split('\n'):
                if "OS details:" in line:
                    os_info = line.split("OS details:")[1].strip()
                    break
                elif "Running:" in line:
                    os_info = line.split("Running:")[1].strip()
                    break
            
            return os_info
        except subprocess.TimeoutExpired:
            return "OS detection timed out"
        except Exception as e:
            logging.error(f"Error detecting OS: {e}")
            return "OS detection error"

    def get_hostname(self, ip_address):
        """Get hostname for an IP address."""
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except:
            return "Unknown"

    def print_device_info(self, mac, device_info, is_new=True):
        """Print device information in a formatted way."""
        status = "NEW DEVICE DETECTED!" if is_new else "Device Info"
        name = self.device_names.get(mac, "Unknown Device")
        ip = device_info.get("ip", "Unknown")
        vendor = device_info.get("vendor", "Unknown")
        os_info = device_info.get("os_info", "Unknown")
        hostname = device_info.get("hostname", "Unknown")

        # Create a formatted box with device information
        print("\n" + "="*60)
        print(f"{Fore.RED if is_new else Fore.GREEN}{status}{Style.RESET_ALL}")
        print("="*60)
        print(f"{Fore.CYAN}Device Name:{Style.RESET_ALL} {name}")
        print(f"{Fore.CYAN}Hostname:{Style.RESET_ALL} {hostname}")
        print(f"{Fore.CYAN}IP Address:{Style.RESET_ALL} {ip}")
        print(f"{Fore.CYAN}MAC Address:{Style.RESET_ALL} {mac}")
        print(f"{Fore.CYAN}Vendor:{Style.RESET_ALL} {vendor}")
        print(f"{Fore.CYAN}Operating System:{Style.RESET_ALL} {os_info}")
        print(f"{Fore.CYAN}First Seen:{Style.RESET_ALL} {device_info.get('first_seen', 'Unknown')}")
        print("="*60 + "\n")

    def scan_network(self):
        """Scan network for connected devices using Windows' arp -a command."""
        devices = {}
        try:
            # Use Windows' arp -a command
            result = subprocess.run(
                ["arp", "-a"], 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            if result.returncode != 0:
                logging.warning(f"arp -a returned non-zero exit code: {result.returncode}")
                return {}
                
            lines = result.stdout.split("\n")
            for line in lines:
                # Windows arp -a output format:
                # Interface: 192.168.1.2 --- 0x4
                #   Internet Address      Physical Address      Type
                #   192.168.1.1          00-11-22-33-44-55     dynamic
                if "dynamic" in line.lower() or "static" in line.lower():
                    parts = [part.strip() for part in line.split() if part.strip()]
                    if len(parts) >= 2:
                        ip_address = parts[0]
                        # Convert Windows format (00-11-22-33-44-55) to standard format (00:11:22:33:44:55)
                        mac_address = parts[1].replace("-", ":").lower()
                        
                        # Skip local/broadcast addresses
                        if mac_address in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
                            continue
                            
                        # Get additional device information
                        hostname = self.get_hostname(ip_address)
                        os_info = self.get_os_info(ip_address)
                            
                        devices[mac_address] = {
                            "ip": ip_address,
                            "vendor": "Unknown",
                            "hostname": hostname,
                            "os_info": os_info,
                            "first_seen": datetime.now().isoformat()
                        }
                    
            return devices
        except subprocess.TimeoutExpired:
            logging.error("Network scan timed out")
            return {}
        except Exception as e:
            logging.error(f"Error scanning network: {e}")
            return {}

    def add_device_name(self, mac_address, name):
        """Add a friendly name for a device."""
        self.device_names[mac_address] = name
        self.save_known_devices()
        logging.info(f"Added name '{name}' for device {mac_address}")

    def monitor(self, duration=None):
        """
        Monitor network for new devices.
        
        Args:
            duration: Optional monitoring duration in seconds. If None, runs indefinitely.
        """
        logging.info("Starting network monitoring...")
        print(f"{Fore.GREEN}Network monitoring started. Press Ctrl+C to stop.{Style.RESET_ALL}\n")
        start_time = time.time()
        
        try:
            while True:
                # Check if duration exceeded
                if duration and (time.time() - start_time > duration):
                    logging.info(f"Monitoring duration of {duration}s completed")
                    break
                    
                # Scan network
                current_devices = self.scan_network()
                current_mac_addresses = set(current_devices.keys())
                
                # Check for new devices
                new_devices = current_mac_addresses - self.known_devices
                if new_devices:
                    for mac in new_devices:
                        device_info = current_devices[mac]
                        
                        # Print device information to terminal
                        self.print_device_info(mac, device_info, is_new=True)
                        
                        # Create notification message
                        name = self.device_names.get(mac, "Unknown Device")
                        message = (
                            f"Name: {name}\n"
                            f"Hostname: {device_info['hostname']}\n"
                            f"IP: {device_info['ip']}\n"
                            f"MAC: {mac}\n"
                            f"OS: {device_info['os_info']}"
                        )
                        
                        # Send system notification
                        try:
                            notification.notify(
                                title="New Device Connected!",
                                message=message,
                                timeout=self.notification_timeout
                            )
                        except Exception as e:
                            logging.error(f"Failed to send notification: {e}")
                    
                    # Update known devices
                    self.known_devices.update(new_devices)
                    self.save_known_devices()
                
                # Dynamic scan interval: more frequent when new devices detected
                sleep_time = max(5, self.scan_interval // 2) if new_devices else self.scan_interval
                logging.debug(f"Sleeping for {sleep_time} seconds...")
                time.sleep(sleep_time)
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Monitoring stopped by user{Style.RESET_ALL}")
            logging.info("Monitoring stopped by user")
        finally:
            self.save_known_devices()
            logging.info("Network monitoring ended")

def main():
    """Main entry point with command-line argument parsing."""
    parser = argparse.ArgumentParser(description="Monitor network for new devices")
    parser.add_argument("--interval", type=int, default=30,
                        help="Scan interval in seconds (default: 30)")
    parser.add_argument("--config", type=str, default="known_devices.json",
                        help="Config file path (default: known_devices.json)")
    parser.add_argument("--duration", type=int, default=None,
                        help="Monitoring duration in seconds (default: indefinite)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Notification timeout in seconds (default: 10)")
    parser.add_argument("--add-name", nargs=2, metavar=("MAC", "NAME"),
                        help="Add a friendly name for a device")
    
    args = parser.parse_args()
    
    monitor = NetworkMonitor(
        config_file=args.config,
        scan_interval=args.interval,
        notification_timeout=args.timeout
    )
    
    if args.add_name:
        mac, name = args.add_name
        monitor.add_device_name(mac, name)
    else:
        monitor.monitor(duration=args.duration)

if __name__ == "__main__":
    main()