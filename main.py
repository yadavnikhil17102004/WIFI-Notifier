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
import re

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
        self.wifi_interface = self.get_wifi_interface()
        if not self.wifi_interface:
            logging.error("No active WiFi interface found!")
            raise Exception("No active WiFi interface found!")
        logging.info(f"Using WiFi interface: {self.wifi_interface}")
        print(f"{Fore.GREEN}Using WiFi interface: {self.wifi_interface}{Style.RESET_ALL}")

    def get_wifi_interface(self):
        """Get the active WiFi interface name."""
        try:
            # Get network interface information using ipconfig
            result = subprocess.run(
                ["ipconfig", "/all"], 
                capture_output=True, 
                text=True, 
                encoding='cp437',  # Use Windows codepage
                timeout=30
            )
            
            if result.returncode != 0:
                logging.error("Failed to run ipconfig /all")
                return None
                
            output = result.stdout
            lines = output.split('\n')
            current_adapter = None
            wifi_adapter = None
            
            # Debug: Print all network adapters found
            print(f"{Fore.YELLOW}Available Network Adapters:{Style.RESET_ALL}")
            
            # First pass: find the Qualcomm Atheros adapter
            for i, line in enumerate(lines):
                line = line.strip()
                
                # Debug: Print each adapter line
                if "adapter" in line.lower():
                    print(f"Found adapter: {line}")
                    current_adapter = line.split(':')[0].strip()
                    
                    # Look ahead for Qualcomm Atheros in description
                    if i + 1 < len(lines) and "Qualcomm Atheros" in lines[i + 1]:
                        wifi_adapter = current_adapter
                        print(f"{Fore.GREEN}Selected WiFi adapter: {wifi_adapter} (Qualcomm Atheros){Style.RESET_ALL}")
                        return wifi_adapter
            
            # If Qualcomm Atheros not found, try finding the main Wi-Fi adapter
            current_adapter = None
            for line in lines:
                line = line.strip()
                
                if "adapter" in line.lower():
                    current_adapter = line.split(':')[0].strip()
                    # Look specifically for the main Wi-Fi adapter
                    if "Wireless LAN adapter Wi-Fi:" in line:
                        wifi_adapter = current_adapter
                        print(f"{Fore.GREEN}Selected WiFi adapter: {wifi_adapter}{Style.RESET_ALL}")
                        return wifi_adapter
            
            # If still not found, try netsh as last resort
            if not wifi_adapter:
                print(f"{Fore.YELLOW}Trying netsh to find WiFi adapter...{Style.RESET_ALL}")
                try:
                    netsh_result = subprocess.run(
                        ["netsh", "wlan", "show", "interfaces"],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if netsh_result.returncode == 0:
                        for line in netsh_result.stdout.split('\n'):
                            if "Name" in line and ":" in line:
                                wifi_adapter = line.split(':')[1].strip()
                                print(f"{Fore.GREEN}Found WiFi adapter using netsh: {wifi_adapter}{Style.RESET_ALL}")
                                return wifi_adapter
                except Exception as e:
                    logging.error(f"Error running netsh: {e}")
            
            if not wifi_adapter:
                print(f"{Fore.RED}No WiFi adapter found!{Style.RESET_ALL}")
            return wifi_adapter
            
        except Exception as e:
            logging.error(f"Error getting WiFi interface: {e}")
            print(f"{Fore.RED}Error detecting WiFi interface: {e}{Style.RESET_ALL}")
            return None

    def get_interface_ip(self):
        """Get the IP address of the WiFi interface."""
        try:
            # Try using netsh first for more reliable results
            print(f"{Fore.YELLOW}Attempting to get IP for interface: {self.wifi_interface}{Style.RESET_ALL}")
            try:
                result = subprocess.run(
                    ["netsh", "interface", "ipv4", "show", "addresses", self.wifi_interface],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    print(f"{Fore.CYAN}netsh output:{Style.RESET_ALL}\n{result.stdout}")
                    for line in result.stdout.split('\n'):
                        if "IP Address:" in line:
                            ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                            if ip_match:
                                ip = ip_match.group(0)
                                print(f"{Fore.GREEN}Found IP using netsh: {ip}{Style.RESET_ALL}")
                                return ip
            except Exception as netsh_error:
                print(f"{Fore.YELLOW}Netsh method failed, falling back to ipconfig: {netsh_error}{Style.RESET_ALL}")
            
            # Fallback to ipconfig
            result = subprocess.run(
                ["ipconfig"], 
                capture_output=True, 
                text=True, 
                encoding='cp437',  # Use Windows codepage
                timeout=30
            )
            
            if result.returncode != 0:
                return None
                
            output = result.stdout
            print(f"{Fore.CYAN}ipconfig output for {self.wifi_interface}:{Style.RESET_ALL}")
            current_adapter = None
            wifi_ip = None
            
            for line in output.split('\n'):
                line = line.strip()
                if self.wifi_interface in line:
                    current_adapter = self.wifi_interface
                    print(f"Found adapter section: {line}")
                elif current_adapter and "IPv4 Address" in line:
                    print(f"Found IP line: {line}")
                    wifi_ip = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                    if wifi_ip:
                        ip = wifi_ip.group(0)
                        print(f"{Fore.GREEN}Found IP using ipconfig: {ip}{Style.RESET_ALL}")
                        return ip
            
            if not wifi_ip:
                print(f"{Fore.RED}Could not find IP address for interface: {self.wifi_interface}{Style.RESET_ALL}")
            
            return None
            
        except Exception as e:
            logging.error(f"Error getting WiFi IP: {e}")
            print(f"{Fore.RED}Error getting WiFi IP: {e}{Style.RESET_ALL}")
            return None

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
        # Skip OS detection since nmap is not installed
        return "OS detection unavailable (nmap not installed)"

    def get_hostname(self, ip_address):
        """Get hostname for an IP address."""
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except:
            return "Unknown"

    def print_device_info(self, mac, device_info, status="NEW"):
        """Print device information in a formatted way."""
        status_colors = {
            "NEW": Fore.GREEN,
            "DISCONNECTED": Fore.RED,
            "EXISTING": Fore.BLUE
        }
        status_text = {
            "NEW": "NEW DEVICE CONNECTED!",
            "DISCONNECTED": "DEVICE DISCONNECTED!",
            "EXISTING": "Device Info"
        }
        
        name = self.device_names.get(mac, "Unknown Device")
        ip = device_info.get("ip", "Unknown")
        vendor = device_info.get("vendor", "Unknown")
        os_info = device_info.get("os_info", "Unknown")
        hostname = device_info.get("hostname", "Unknown")
        interface = device_info.get("interface", "Unknown")

        # Create a formatted box with device information
        print("\n" + "="*60)
        print(f"{status_colors.get(status, Fore.WHITE)}{status_text.get(status, status)}{Style.RESET_ALL}")
        print("="*60)
        print(f"{Fore.CYAN}Device Name:{Style.RESET_ALL} {name}")
        print(f"{Fore.CYAN}Hostname:{Style.RESET_ALL} {hostname}")
        print(f"{Fore.CYAN}IP Address:{Style.RESET_ALL} {ip}")
        print(f"{Fore.CYAN}MAC Address:{Style.RESET_ALL} {mac}")
        print(f"{Fore.CYAN}Vendor:{Style.RESET_ALL} {vendor}")
        print(f"{Fore.CYAN}Operating System:{Style.RESET_ALL} {os_info}")
        print(f"{Fore.CYAN}Network Interface:{Style.RESET_ALL} {interface}")
        if "first_seen" in device_info:
            print(f"{Fore.CYAN}First Seen:{Style.RESET_ALL} {device_info['first_seen']}")
        if "last_seen" in device_info:
            print(f"{Fore.CYAN}Last Seen:{Style.RESET_ALL} {device_info['last_seen']}")
        print("="*60 + "\n")

    def notify_device_status(self, mac, device_info, status="NEW"):
        """Send notification about device status change."""
        name = self.device_names.get(mac, "Unknown Device")
        title = "New Device Connected!" if status == "NEW" else "Device Disconnected!"
        color = Fore.GREEN if status == "NEW" else Fore.RED
        
        message = (
            f"Name: {name}\n"
            f"Hostname: {device_info['hostname']}\n"
            f"IP: {device_info['ip']}\n"
            f"MAC: {mac}\n"
            f"Status: {'Connected' if status == 'NEW' else 'Disconnected'}"
        )
        
        # Print to terminal
        print(f"{color}{title}{Style.RESET_ALL}")
        print(message)
        print()
        
        # Send system notification
        try:
            notification.notify(
                title=title,
                message=message,
                timeout=self.notification_timeout
            )
        except Exception as e:
            logging.error(f"Failed to send notification: {e}")

    def scan_network(self):
        """Scan network for connected devices using Windows' arp -a command."""
        devices = {}
        try:
            # Get the WiFi interface IP
            interface_ip = self.get_interface_ip()
            if not interface_ip:
                print(f"{Fore.RED}Could not determine WiFi interface IP{Style.RESET_ALL}")
                return {}

            print(f"\n{Fore.CYAN}Scanning network for interface IP: {interface_ip}{Style.RESET_ALL}")
            
            # First, ping the gateway to ensure ARP cache is populated
            gateway_ip = '.'.join(interface_ip.split('.')[:-1] + ['1'])
            print(f"{Fore.YELLOW}Pinging gateway ({gateway_ip}) to populate ARP cache...{Style.RESET_ALL}")
            subprocess.run(
                ["ping", "-n", "1", gateway_ip],
                capture_output=True,
                timeout=5
            )

            # Use Windows' arp -a command with specific interface
            print(f"{Fore.YELLOW}Running: arp -a -N {interface_ip}{Style.RESET_ALL}")
            result = subprocess.run(
                ["arp", "-a", "-N", interface_ip], 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            if result.returncode != 0:
                print(f"{Fore.RED}arp -a returned non-zero exit code: {result.returncode}{Style.RESET_ALL}")
                return {}
                
            print(f"{Fore.CYAN}arp -a output:{Style.RESET_ALL}\n{result.stdout}")
            
            lines = result.stdout.split("\n")
            interface_section = False
            
            for line in lines:
                # Check if this is the section for our interface
                if "Interface:" in line:
                    if interface_ip in line:
                        interface_section = True
                        print(f"{Fore.GREEN}Found interface section: {line}{Style.RESET_ALL}")
                    else:
                        interface_section = False
                    continue

                if not interface_section:
                    continue

                if "dynamic" in line.lower() or "static" in line.lower():
                    parts = [part.strip() for part in line.split() if part.strip()]
                    if len(parts) >= 2:
                        ip_address = parts[0]
                        mac_address = parts[1].replace("-", ":").lower()
                        
                        # Skip local/broadcast addresses
                        if mac_address in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
                            continue
                            
                        print(f"{Fore.GREEN}Found device - IP: {ip_address}, MAC: {mac_address}{Style.RESET_ALL}")
                        
                        # Get additional device information
                        hostname = self.get_hostname(ip_address)
                            
                        devices[mac_address] = {
                            "ip": ip_address,
                            "vendor": "Unknown",
                            "hostname": hostname,
                            "os_info": "OS detection unavailable",
                            "first_seen": datetime.now().isoformat(),
                            "interface": self.wifi_interface
                        }
                    
            return devices
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}Network scan timed out{Style.RESET_ALL}")
            return {}
        except Exception as e:
            print(f"{Fore.RED}Error scanning network: {e}{Style.RESET_ALL}")
            return {}

    def add_device_name(self, mac_address, name):
        """Add a friendly name for a device."""
        self.device_names[mac_address] = name
        self.save_known_devices()
        logging.info(f"Added name '{name}' for device {mac_address}")

    def monitor(self, duration=None):
        """
        Monitor network for new devices and disconnections.
        
        Args:
            duration: Optional monitoring duration in seconds. If None, runs indefinitely.
        """
        logging.info("Starting network monitoring...")
        print(f"{Fore.GREEN}Network monitoring started. Press Ctrl+C to stop.{Style.RESET_ALL}\n")
        start_time = time.time()
        
        # Store last seen time for each device
        device_last_seen = {}
        disconnection_timeout = 60  # Consider device disconnected after 60 seconds of no response
        
        try:
            while True:
                # Check if duration exceeded
                if duration and (time.time() - start_time > duration):
                    logging.info(f"Monitoring duration of {duration}s completed")
                    break
                    
                # Scan network
                current_devices = self.scan_network()
                current_time = time.time()
                current_mac_addresses = set(current_devices.keys())
                
                # Check for new devices
                new_devices = current_mac_addresses - self.known_devices
                if new_devices:
                    for mac in new_devices:
                        device_info = current_devices[mac]
                        device_last_seen[mac] = current_time
                        
                        # Print and notify about new device
                        self.print_device_info(mac, device_info, status="NEW")
                        self.notify_device_status(mac, device_info, status="NEW")
                    
                    # Update known devices
                    self.known_devices.update(new_devices)
                    self.save_known_devices()
                
                # Update last seen time for all current devices
                for mac in current_mac_addresses:
                    device_last_seen[mac] = current_time
                
                # Check for disconnected devices
                for mac in list(self.known_devices):
                    if mac not in current_mac_addresses:
                        last_seen = device_last_seen.get(mac, 0)
                        if current_time - last_seen > disconnection_timeout:
                            # Device hasn't been seen for a while, consider it disconnected
                            if mac in self.known_devices:
                                device_info = {
                                    "ip": "Last known",
                                    "hostname": "Disconnected",
                                    "vendor": "Unknown",
                                    "os_info": "Unavailable",
                                    "interface": self.wifi_interface,
                                    "last_seen": datetime.fromtimestamp(last_seen).isoformat()
                                }
                                
                                # Print and notify about disconnected device
                                self.print_device_info(mac, device_info, status="DISCONNECTED")
                                self.notify_device_status(mac, device_info, status="DISCONNECTED")
                                
                                # Remove from known devices
                                self.known_devices.remove(mac)
                                if mac in device_last_seen:
                                    del device_last_seen[mac]
                
                # Dynamic scan interval: more frequent when changes detected
                sleep_time = max(5, self.scan_interval // 2) if new_devices else self.scan_interval
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