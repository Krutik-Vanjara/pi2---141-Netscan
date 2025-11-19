

## **Step 1: Set Up GNS3 in VMware**
### **1. Install GNS3 and VMware Integration**
1. **Download and Install GNS3**:
   - Download from [GNS3 Official Site](https://www.gns3.com/software/download).
   - Install GNS3 and the VMware Workstation integration.

2. **Set Up GNS3 VM**:
   - GNS3 requires a **GNS3 VM** (based on Ubuntu) to run network devices.
   - Import the GNS3 VM into VMware Workstation.

3. **Configure VMware in GNS3**:
   - Open GNS3 → **Edit** → **Preferences** → **VMware** → Add VMware Workstation as a hypervisor.

---

## **Step 2: Create a Virtual Network in GNS3**
### **1. Add Devices to GNS3**
1. **Add a Switch**:
   - Drag and drop an **Ethernet switch** from the devices panel.

2. **Add a Router**:
   - Drag and drop a **Cisco router** (e.g., Cisco 3725) or use a **Linux router** (e.g., VyOS).

3. **Add IoT Devices**:
   - Use **Docker containers** or **QEMU VMs** to simulate IoT devices.
   - Example: Add a **Raspberry Pi VM** or a **Docker container running MQTT**.

4. **Add a Printer**:
   - Use a **Linux VM** with CUPS installed to simulate a printer.
   - Example: Ubuntu VM with `sudo apt install cups`.

5. **Add PCs/Laptops**:
   - Use **Windows/Linux VMs** in VMware and connect them to the GNS3 network.

---

### **Step 3: Connect Devices**
1. **Connect Switch to Router**:
   - Drag a link from the switch to the router.

2. **Connect IoT Devices and Printers**:
   - Connect IoT devices and printers to the switch.

3. **Connect PCs/Laptops**:
   - Connect VMs to the switch.

---

### **Step 4: Configure IP Addresses**
1. **Router Configuration**:
   - Assign an IP to the router interface connected to the switch (e.g., `192.168.100.1`).

2. **IoT Device Configuration**:
   - Assign IPs to IoT devices (e.g., `192.168.100.2`, `192.168.100.3`).

3. **Printer Configuration**:
   - Assign an IP to the printer VM (e.g., `192.168.100.4`).

4. **PC/Laptop Configuration**:
   - Assign IPs to PC/Laptop VMs (e.g., `192.168.100.5`, `192.168.100.6`).

---

## **Step 5: Updated Script for GNS3 Virtual Network**
### **`network_scanner_gns3.py`**
```python
#!/usr/bin/env python3
import argparse
import logging
import subprocess
import yaml
import os
import pandas as pd
from datetime import datetime
import python_nmap

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, config_path="config.yaml"):
        self.config = self._load_config(config_path)
        self.local_ip = self._get_local_ip()

    def _load_config(self, config_path):
        """Load configuration from YAML file."""
        default_config = {
            "oui_database": {
                # Routers/Switches
                "00:1A:79": "Cisco",
                "00:0D:4B": "Dell",
                "00:1C:B3": "HP",
                "00:1B:44": "Intel",
                "00:13:72": "Dell",
                "00:1E:68": "Samsung",
                "00:1F:33": "Apple",
                "B8:27:EB": "Raspberry Pi",
                "00:1B:44": "Intel",
                "00:1C:14": "Microsoft",
                "00:0C:29": "VMware",
                # Printers
                "00:17:AB": "Elitegroup Computer Systems",
                "00:1E:4F": "Brother Industries",
                "00:21:70": "Dell",
                "00:16:3E": "Xerox",
                # IoT Devices
                "3C:5A:B4": "Google",
                "70:EE:50": "Samsung Electronics",
                "B8:27:EB": "Raspberry Pi",
                "DC:A6:32": "Apple",
                "E0:DB:55": "Dell",
                "F0:18:98": "Apple",
                "00:08:74": "Dell",
                "00:16:3E": "Xensource",
                "00:1C:14": "Microsoft",
                "00:50:56": "VMware",
                "08:00:27": "Cadmus Computer Systems",
                "5C:F7:E6": "Apple",
                "A4:83:E7": "Apple",
                "00:1B:44": "Cisco",
                "00:1D:0F": "Apple",
                "00:21:5A": "Hewlett Packard",
                "00:23:12": "Apple",
                "00:25:4B": "Apple",
                "00:26:BB": "Apple",
                "3C:07:54": "Apple",
                "3C:15:C2": "Apple",
                "3C:22:FB": "Apple",
                "3C:AB:8E": "Apple",
                "60:F1:89": "Apple",
                "78:31:C1": "Apple",
                "8C:85:90": "Apple",
                "A8:20:66": "Apple",
                "C8:2A:14": "Apple",
                "D8:30:62": "Apple",
                "F0:18:98": "Apple",
                # Smart Home Devices
                "3C:5A:B4": "Google",
                "70:EE:50": "Samsung Electronics",
                "44:65:0D": "Amazon Technologies",
                "7C:2E:BD": "Amazon Technologies",
                "A0:02:DC": "Amazon Technologies",
                # Gaming Consoles
                "00:21:70": "Dell",
                "00:24:BE": "Nintendo",
                "00:26:5E": "Nintendo",
                "78:E3:B5": "Nintendo",
                # Virtual Machines
                "00:0C:29": "VMware",
                "00:16:3E": "Xensource",
                "00:1C:14": "Microsoft",
            },
            "nmap_args": "-sn",  # Ping scan only for GNS3
            "log_file": "scanner.log",
            "alert_file": "alerts.log"
        }
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
                default_config.update(config)
        return default_config

    def _get_local_ip(self):
        """Get the local IP address of the GNS3 VM or host."""
        try:
            # For GNS3 VM, use ifconfig or ip
            result = subprocess.run(["ip", "a"], capture_output=True, text=True, check=True)
            output = result.stdout
            for line in output.split('\n'):
                if "inet 192.168" in line and "global" in line:
                    ip = line.split()[1].split('/')[0]
                    return ip
            logger.error("Could not determine local IP address.")
            return None
        except Exception as e:
            logger.error(f"Error getting local IP: {e}")
            return None

    def arp_scan(self, interface="eth0"):
        """Perform ARP scan to discover devices using Nmap."""
        if not self.local_ip:
            logger.error("No local IP address found.")
            return []

        # Extract the subnet from the local IP
        ip_parts = self.local_ip.split('.')
        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

        logger.info(f"Scanning {subnet} via Nmap...")
        nm = python_nmap.PortScanner()
        try:
            nm.scan(hosts=subnet, arguments=self.config["nmap_args"])
            devices = []
            for host in nm.all_hosts():
                if host != self.local_ip:  # Skip the local machine
                    mac = nm[host].vendor.get(nm[host].addresses.get('mac'), {}).get('vendor', 'Unknown')
                    devices.append({
                        "ip": host,
                        "mac": nm[host].addresses.get('mac', 'Unknown'),
                        "vendor": mac
                    })
            return devices
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
            return []

    def port_scan(self, target_ip):
        """Scan for open ports on a target IP using Nmap."""
        logger.info(f"Scanning ports for {target_ip}...")
        nm = python_nmap.PortScanner()
        try:
            nm.scan(hosts=target_ip, arguments="-sV -T4")
            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        open_ports.append({
                            "port": port,
                            "service": nm[host][proto][port]['name'],
                            "version": nm[host][proto][port].get('version', 'Unknown')
                        })
            return open_ports
        except Exception as e:
            logger.error(f"Port scan failed: {e}")
            return []

    def classify_device(self, device):
        """Classify a device based on MAC vendor and open ports."""
        mac = device["mac"]
        ip = device["ip"]
        vendor = device["vendor"]

        # Default classification
        device_type = "Unknown"

        # Classify by vendor
        vendor_lower = vendor.lower()
        if any(x in vendor_lower for x in ["apple", "dell", "hp", "lenovo", "asus", "acer", "msi", "microsoft"]):
            device_type = "Laptop/PC"
        elif any(x in vendor_lower for x in ["brother", "xerox", "canon", "hp", "epson", "samsung"]):
            device_type = "Printer"
        elif any(x in vendor_lower for x in ["raspberry pi", "arduino", "espressif", "amazon technologies"]):
            device_type = "IoT Device"
        elif any(x in vendor_lower for x in ["cisco", "netgear", "tp-link", "d-link", "asus"]):
            device_type = "Router/Switch"
        elif any(x in vendor_lower for x in ["samsung", "lg", "sony", "vizio", "tcl"]):
            device_type = "Smart TV"
        elif any(x in vendor_lower for x in ["google", "amazon technologies", "nest"]):
            device_type = "Smart Home Device"
        elif any(x in vendor_lower for x in ["nintendo", "sony", "microsoft"]):
            device_type = "Gaming Console"
        elif any(x in vendor_lower for x in ["vmware", "xensource", "virtualbox", "microsoft corporation"]):
            device_type = "Virtual Machine"

        # Further classify by open ports (if available)
        open_ports = self.port_scan(ip)
        if open_ports:
            for port_info in open_ports:
                port = port_info["port"]
                service = port_info["service"].lower()
                if port in [22, 3389, 5900, 5901]:
                    device_type = "Laptop/PC"  # SSH, RDP, VNC
                elif port in [80, 443, 8080]:
                    if device_type == "Unknown":
                        device_type = "Web Server"
                elif port in [137, 138, 139, 445]:
                    device_type = "Windows PC"  # SMB ports
                elif port in [631, 9100, 9220, 9290]:
                    device_type = "Printer"
                elif port in [1883, 8883]:
                    device_type = "IoT Device"  # MQTT
                elif port in [1935, 554, 8080, 8200]:
                    device_type = "Smart TV"  # RTMP, RTSP
                elif port in [1900, 3702, 5353]:
                    device_type = "Smart Home Device"  # UPnP, MDNS
                elif port in [1935, 8554]:
                    device_type = "Streaming Device"  # RTMP, RTSP

        return device_type

    def visualize_devices(self, devices):
        """Visualize device types using pandas."""
        data = []
        for device in devices:
            device_type = self.classify_device(device)
            data.append({
                "IP": device["ip"],
                "MAC": device["mac"],
                "Vendor": device["vendor"],
                "Type": device_type
            })

        df = pd.DataFrame(data)
        logger.info("\nDevice Type Summary:")
        logger.info(df.groupby("Type").size().to_string())

        # Save to CSV
        df.to_csv("device_summary.csv", index=False)
        logger.info("Device summary saved to device_summary.csv")

    def log_alert(self, message):
        """Log alerts to file."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert = f"[{timestamp}] {message}\n"
        with open(self.config["alert_file"], "a") as f:
            f.write(alert)
        logger.info(f"Alert logged: {message}")

    def run(self, scan_type="full", target_ip=None):
        """Run the scanner based on user input."""
        if scan_type in ["full", "arp"]:
            devices = self.arp_scan()
            if not devices:
                logger.warning("No devices found.")
                return
            logger.info("\nDiscovered Devices:")
            for device in devices:
                device_type = self.classify_device(device)
                logger.info(f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}, Type: {device_type}")

            self.visualize_devices(devices)  # Visualize device types

        if scan_type in ["full", "ports"]:
            target = target_ip if target_ip else self.local_ip
            if not target:
                logger.error("No target IP specified.")
                return
            open_ports = self.port_scan(target)
            if open_ports:
                logger.info(f"\nOpen Ports for {target}:")
                for port_info in open_ports:
                    logger.info(f"  Port {port_info['port']}: {port_info['service']} ({port_info['version']})")
                    self.log_alert(f"Open port detected: {target}:{port_info['port']} ({port_info['service']})")
            else:
                logger.info(f"No open ports found for {target}")

def main():
    parser = argparse.ArgumentParser(
        description="Network Scanner CLI Tool for GNS3 Virtual Networks",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--scan",
        choices=["full", "arp", "ports"],
        default="full",
        help="Scan type: full (ARP + ports), arp (ARP only), ports (ports only)"
    )
    parser.add_argument(
        "--target",
        type=str,
        help="Target IP or range (default: local subnet)"
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Path to config file (default: config.yaml)"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    scanner = NetworkScanner(config_path=args.config)
    scanner.run(scan_type=args.scan, target_ip=args.target)

if __name__ == "__main__":
    main()
```

---

### **Updated `config.yaml`**
```yaml
# Custom OUI database entries
oui_database:
  # Routers/Switches
  "00:1A:79": "Cisco"
  "00:0D:4B": "Dell"
  "00:1C:B3": "HP"
  "00:1B:44": "Intel"
  "00:13:72": "Dell"
  "00:1E:68": "Samsung"
  "00:1F:33": "Apple"
  "B8:27:EB": "Raspberry Pi"
  "00:1B:44": "Intel"
  "00:1C:14": "Microsoft"
  "00:0C:29": "VMware"
  # Printers
  "00:17:AB": "Elitegroup Computer Systems"
  "00:1E:4F": "Brother Industries"
  "00:21:70": "Dell"
  "00:16:3E": "Xerox"
  # IoT Devices
  "3C:5A:B4": "Google"
  "70:EE:50": "Samsung Electronics"
  "B8:27:EB": "Raspberry Pi"
  "DC:A6:32": "Apple"
  "E0:DB:55": "Dell"
  "F0:18:98": "Apple"
  "00:08:74": "Dell"
  "00:16:3E": "Xensource"
  "00:1C:14": "Microsoft"
  "00:50:56": "VMware"
  "08:00:27": "Cadmus Computer Systems"
  "5C:F7:E6": "Apple"
  "A4:83:E7": "Apple"
  "00:1B:44": "Cisco"
  "00:1D:0F": "Apple"
  "00:21:5A": "Hewlett Packard"
  "00:23:12": "Apple"
  "00:25:4B": "Apple"
  "00:26:BB": "Apple"
  "3C:07:54": "Apple"
  "3C:15:C2": "Apple"
  "3C:22:FB": "Apple"
  "3C:AB:8E": "Apple"
  "60:F1:89": "Apple"
  "78:31:C1": "Apple"
  "8C:85:90": "Apple"
  "A8:20:66": "Apple"
  "C8:2A:14": "Apple"
  "D8:30:62": "Apple"
  "F0:18:98": "Apple"
  # Smart Home Devices
  "3C:5A:B4": "Google"
  "70:EE:50": "Samsung Electronics"
  "44:65:0D": "Amazon Technologies"
  "7C:2E:BD": "Amazon Technologies"
  "A0:02:DC": "Amazon Technologies"
  # Gaming Consoles
  "00:21:70": "Dell"
  "00:24:BE": "Nintendo"
  "00:26:5E": "Nintendo"
  "78:E3:B5": "Nintendo"
  # Virtual Machines
  "00:0C:29": "VMware"
  "00:16:3E": "Xensource"
  "00:1C:14": "Microsoft"

# Nmap arguments for GNS3
nmap_args: "-sn"  # Ping scan only

# Log files
log_file: "scanner.log"
alert_file: "alerts.log"
```

---

## **Step 6: How the Script Works (Architecture)**
### **1. Initialization**
- The script initializes by loading the configuration from `config.yaml`.
- It detects the local IP address of the GNS3 VM or host.

### **2. ARP Scan**
- Uses **Nmap** to perform a **ping scan** (`-sn`) on the local subnet.
- Detects live hosts and retrieves their **IPs, MAC addresses, and vendors**.

### **3. Port Scan**
- Uses **Nmap** to scan open ports on a target IP.
- Retrieves **port numbers, services, and versions**.

### **4. Device Classification**
- Classifies devices based on:
  - **MAC vendor** (e.g., Apple, Dell, HP).
  - **Open ports** (e.g., port 22 for SSH, port 80 for HTTP).

### **5. Visualization**
- Uses **Pandas** to generate a summary of device types.
- Saves the summary to `device_summary.csv`.

### **6. Logging**
- Logs alerts to `alerts.log` and general output to `scanner.log`.

---
## **Architecture Diagramme**
![my image](web1.excalidraw%20%282%29.png)


---
## **Step 7: Run the Script in GNS3**
1. **Open a terminal in your GNS3 VM**.
2. **Run a Full Scan**:
   ```bash
   python3 network_scanner_gns3.py --scan full
   ```
   - **Expected Output**:
     ```
     2023-11-20 12:34:56,789 - INFO - Scanning 192.168.100.0/24 via Nmap...
     2023-11-20 12:34:56,789 - INFO -
     Discovered Devices:
     IP: 192.168.100.2, MAC: 00:0D:4B:DD:EE:FF, Vendor: Dell, Type: Laptop/PC
     IP: 192.168.100.3, MAC: B8:27:EB:11:22:33, Vendor: Raspberry Pi, Type: IoT Device
     IP: 192.168.100.4, MAC: 00:1C:B3:44:55:66, Vendor: HP, Type: Printer

     2023-11-20 12:34:56,789 - INFO - Device Type Summary:
     Type
     IoT Device           1
     Laptop/PC            1
     Printer              1
     ```

3. **Run Specific Scans**:
   - **ARP Scan Only**:
     ```bash
     python3 network_scanner_gns3.py --scan arp
     ```
   - **Port Scan for a Specific IP**:
     ```bash
     python3 network_scanner_gns3.py --scan ports --target 192.168.100.3
     ```
   - **Debug Mode**:
     ```bash
     python3 network_scanner_gns3.py --scan full --debug
     ```

---

## **Step 8: Architecture Explanation**
### **1. Command Execution Flow**
1. **User Input**:
   - The user runs the script with arguments (e.g., `--scan full`).

2. **Initialization**:
   - The script loads the configuration and detects the local IP.

3. **ARP Scan**:
   - Nmap performs a ping scan on the subnet to discover live hosts.

4. **Port Scan**:
   - Nmap scans open ports on each discovered host.

5. **Device Classification**:
   - The script classifies each device based on MAC vendor and open ports.

6. **Visualization**:
   - Pandas generates a summary of device types and saves it to a CSV file.

7. **Logging**:
   - Alerts and logs are saved to files for further analysis.

---

## **Step 9: Example Virtual Network in GNS3**
| **Device**          | **IP Address**       | **MAC Address**       | **Type**          |
|---------------------|----------------------|-----------------------|-------------------|
| Cisco Router        | 192.168.100.1        | 00:1A:79:AA:BB:CC     | Router/Switch     |
| Dell Laptop         | 192.168.100.2        | 00:0D:4B:DD:EE:FF     | Laptop/PC         |
| Raspberry Pi       | 192.168.100.3        | B8:27:EB:11:22:33     | IoT Device        |
| HP Printer          | 192.168.100.4        | 00:1C:B3:44:55:66     | Printer           |
| Samsung Smart TV    | 192.168.100.5        | 70:EE:50:44:55:66     | Smart TV          |

---

## **Step 10: Troubleshooting**
| **Issue**               | **Solution**                                  |
|-------------------------|---------------------------------------------|
| Nmap not found          | Install Nmap in the GNS3 VM: `sudo apt install nmap`. |
| No devices found        | Ensure all devices are powered on and connected. |
| Permission denied       | Run the script with `sudo`.                 |
| Incorrect IP subnet     | Check the local IP with `ip a`.             |

