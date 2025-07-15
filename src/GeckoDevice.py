import os
import sys
import subprocess
import platform
import socket
import requests
import re
import json
import time
import random
from datetime import datetime

def set_random_color():
    if platform.system() == "Windows":
        colors = [
            1,   # Blue
            2,   # Green
            3,   # Cyan
            4,   # Red
            5,   # Magenta
            6,   # Yellow
            7,   # White
            9,   # Light Blue
            10,  # Light Green
            11,  # Light Cyan
            12,  # Light Red
            13,  # Light Magenta
            14,  # Light Yellow
            15   # Bright White
        ]
        color = random.choice(colors)
        os.system(f'color {color:02x}')
        return color
    else:
        colors = [
            '\033[91m',  # Red
            '\033[92m',  # Green
            '\033[93m',  # Yellow
            '\033[94m',  # Blue
            '\033[95m',  # Magenta
            '\033[96m',  # Cyan
            '\033[97m',  # White
            '\033[31m',  # Bright Red
            '\033[32m',  # Bright Green
            '\033[33m',  # Bright Yellow
            '\033[34m',  # Bright Blue
            '\033[35m',  # Bright Magenta
            '\033[36m',  # Bright Cyan
        ]
        color = random.choice(colors)
        print(color, end='')
        return color

def reset_color():
    """Reset terminal color"""
    if platform.system() == "Windows":
        os.system('color 07')  # Reset to default white on black
    else:
        print('\033[0m', end='')

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_banner():
    """Display the GeckoDevice banner"""
    print("                         d8b                         d8b                   d8,                                           d8b ")
    print("                         ?88                         88P                  `8P                      d8P                   88P ")
    print("                          88b                       d88                                         d888888P                d88  ")
    print(" d888b8b   d8888b d8888b  888  d88' d8888b      d888888   d8888b?88   d8P  88b d8888b d8888b      ?88'   d8888b  d8888b 888  ")
    print("d8P' ?88  d8b_,dPd8P' `P  888bd8P' d8P' ?88    d8P' ?88  d8b_,dPd88  d8P'  88Pd8P' `Pd8b_,dP      88P   d8P' ?88d8P' ?88?88  ")
    print("88b  ,88b 88b    88b     d88888b   88b  d88    88b  ,88b 88b    ?8b ,88'  d88 88b    88b          88b   88b  d8888b  d88 88b ")
    print("`?88P'`88b`?888P'`?888P'd88' `?88b,`?8888P'    `?88P'`88b`?888P'`?888P'  d88' `?888P'`?888P'      `?8b  `?8888P'`?8888P'  88b")
    print("       )88                                                                                                                   ")
    print("      ,88P                                                                                                                   ")
    print("  `?8888P                                                                                                                    ")
    print("======🔍 Welcome to Gecko Device Tool")
    print("💡 Choose an option from the menu below")
    print()

def get_public_ip():
    """Get the device's public IP address"""
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        return response.json()['ip']
    except:
        try:
            response = requests.get('https://httpbin.org/ip', timeout=5)
            return response.json()['origin']
        except:
            return "Unable to retrieve"

def get_private_ip():
    """Get the device's private IP address"""
    try:
        # Create a socket to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "Unable to retrieve"

def get_hostname():
    """Get the device's hostname"""
    try:
        return socket.gethostname()
    except:
        return "Unable to retrieve"

def get_vendor_info():
    """Get device vendor information"""
    try:
        if platform.system() == "Windows":
            # Get manufacturer from Windows
            result = subprocess.run(['wmic', 'computersystem', 'get', 'manufacturer'], 
                                  capture_output=True, text=True, shell=True)
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2:
                manufacturer = lines[1].strip()
                if manufacturer and manufacturer != "Manufacturer":
                    return manufacturer
        elif platform.system() == "Linux":
            # Try to get vendor from /sys/class/dmi/id/product_vendor
            try:
                with open('/sys/class/dmi/id/product_vendor', 'r') as f:
                    vendor = f.read().strip()
                    if vendor:
                        return vendor
            except:
                pass
            
            # Try dmidecode if available
            try:
                result = subprocess.run(['dmidecode', '-s', 'system-manufacturer'], 
                                      capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except:
                pass
        elif platform.system() == "Darwin":  # macOS
            result = subprocess.run(['system_profiler', 'SPHardwareDataType'], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'Vendor' in line or 'Manufacturer' in line:
                    vendor = line.split(':')[-1].strip()
                    if vendor:
                        return vendor
    except:
        pass
    
    return "Unknown"

def get_fingerprint_info():
    """Get comprehensive device fingerprint information"""
    print("🔍 Gathering Device Fingerprint Information...")
    print()
    
    # Get all fingerprint data
    public_ip = get_public_ip()
    private_ip = get_private_ip()
    hostname = get_hostname()
    vendor = get_vendor_info()
    
    # Display results
    print("📊 Device Fingerprint Information:")
    print("="*50)
    print(f"🌐 Public IP Address:  {public_ip}")
    print(f"🏠 Private IP Address: {private_ip}")
    print(f"📝 Hostname:           {hostname}")
    print(f"🏭 Vendor/Manufacturer:{vendor}")
    print(f"💻 Operating System:   {platform.system()} {platform.release()}")
    print(f"🔧 Architecture:       {platform.machine()}")
    print(f"🐍 Python Version:     {platform.python_version()}")
    print("="*50)
    print()

def get_wifi_passwords_windows():
    """Get WiFi passwords on Windows"""
    try:
        # Get WiFi profiles
        result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], 
                              capture_output=True, text=True, shell=True)
        
        if result.returncode != 0:
            print("❌ Error: Unable to retrieve WiFi profiles")
            return
        
        # Extract profile names
        profiles = []
        for line in result.stdout.split('\n'):
            if 'All User Profile' in line or 'All Users Profile' in line:
                profile = line.split(':')[-1].strip()
                if profile:
                    profiles.append(profile)
        
        if not profiles:
            print("⚠️  No WiFi profiles found")
            return
        
        print(f"✅ Found {len(profiles)} WiFi profiles")
        print()
        
        # Get password for each profile
        for i, profile in enumerate(profiles, 1):
            print(f"📡 [{i}/{len(profiles)}] Profile: {profile}")
            
            # Get password for this profile
            cmd = f'netsh wlan show profile name="{profile}" key=clear'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                # Extract password
                password = None
                for line in result.stdout.split('\n'):
                    if 'Key Content' in line:
                        password = line.split(':')[-1].strip()
                        break
                
                if password:
                    print(f"🔑   Password: {password}")
                else:
                    print(f"🔒   Password: Not stored")
            else:
                print(f"❌   Error retrieving password")
            
            print()
    
    except Exception as e:
        print(f"❌ Error: {str(e)}")

def get_wifi_passwords_linux():
    """Get WiFi passwords on Linux"""
    try:
        # Check if NetworkManager is available
        result = subprocess.run(['which', 'nmcli'], capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ NetworkManager (nmcli) not found")
            return
        
        # Get WiFi connections
        result = subprocess.run(['nmcli', '-t', '-f', 'NAME,TYPE,DEVICE', 'connection', 'show'], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            print("❌ Error retrieving WiFi connections")
            return
        
        wifi_connections = []
        for line in result.stdout.split('\n'):
            if line and 'wifi' in line.lower():
                parts = line.split(':')
                if len(parts) >= 3:
                    name = parts[0]
                    wifi_connections.append(name)
        
        if not wifi_connections:
            print("⚠️  No WiFi connections found")
            return
        
        print(f"✅ Found {len(wifi_connections)} WiFi connections")
        print()
        
        # Try to get passwords (requires sudo)
        for i, connection in enumerate(wifi_connections, 1):
            print(f"📡 [{i}/{len(wifi_connections)}] Connection: {connection}")
            
            # Try to get password from NetworkManager
            result = subprocess.run(['sudo', 'cat', f'/etc/NetworkManager/system-connections/{connection}.nmconnection'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                # Extract password
                password = None
                for line in result.stdout.split('\n'):
                    if 'psk=' in line:
                        password = line.split('=')[-1].strip()
                        break
                
                if password:
                    print(f"🔑   Password: {password}")
                else:
                    print(f"🔒   Password: Not stored")
            else:
                print(f"🔒   Password: Requires elevated privileges")
            
            print()
    
    except Exception as e:
        print(f"❌ Error: {str(e)}")

def get_wifi_passwords_macos():
    """Get WiFi passwords on macOS"""
    try:
        # Get WiFi networks from keychain
        result = subprocess.run(['security', 'find-generic-password', '-D', 'AirPort network password', '-g'], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            print("❌ Error accessing keychain")
            return
        
        # Parse the output to extract network names and passwords
        networks = []
        current_network = None
        
        for line in result.stdout.split('\n'):
            if '"ssid"<blob>=' in line:
                current_network = line.split('=')[-1].strip().strip('"')
            elif '"ssid"<blob>=' in line and current_network:
                password = line.split('=')[-1].strip().strip('"')
                networks.append((current_network, password))
                current_network = None
        
        if not networks:
            print("⚠️  No WiFi passwords found in keychain")
            return
        
        print(f"✅ Found {len(networks)} WiFi networks with passwords")
        print()
        
        for i, (network, password) in enumerate(networks, 1):
            print(f"📡 [{i}/{len(networks)}] Network: {network}")
            print(f"🔑   Password: {password}")
            print()
    
    except Exception as e:
        print(f"❌ Error: {str(e)}")

def get_wifi_passwords():
    """Get WiFi passwords based on the operating system"""
    print("🔍 Retrieving WiFi Passwords...")
    print()
    
    system = platform.system()
    
    if system == "Windows":
        get_wifi_passwords_windows()
    elif system == "Linux":
        get_wifi_passwords_linux()
    elif system == "Darwin":  # macOS
        get_wifi_passwords_macos()
    else:
        print(f"❌ Unsupported operating system: {system}")

def get_storage_info():
    """Get storage device information"""
    print("💾 Gathering Storage Information...")
    print()
    
    system = platform.system()
    
    if system == "Windows":
        get_storage_info_windows()
    elif system == "Linux":
        get_storage_info_linux()
    elif system == "Darwin":  # macOS
        get_storage_info_macos()
    else:
        print(f"❌ Unsupported operating system: {system}")

def get_storage_info_windows():
    """Get storage information on Windows"""
    try:
        # Get logical disk information
        result = subprocess.run(['wmic', 'logicaldisk', 'get', 'size,freespace,caption,volumename'], 
                              capture_output=True, text=True, shell=True)
        
        if result.returncode != 0:
            print("❌ Error: Unable to retrieve storage information")
            return
        
        lines = result.stdout.strip().split('\n')
        if len(lines) < 2:
            print("❌ No storage devices found")
            return
        
        print("💾 Storage Devices:")
        print("="*80)
        
        # Skip header line
        for line in lines[1:]:
            if line.strip():
                parts = line.strip().split()
                if len(parts) >= 4:
                    drive = parts[0]
                    free = int(parts[1]) if parts[1].isdigit() else 0  # FreeSpace is column 1
                    size = int(parts[2]) if parts[2].isdigit() else 0  # Size is column 2
                    used = size - free
                    volume_name = ' '.join(parts[3:]) if len(parts) > 3 else "No Label"
                    
                    # Convert to GB
                    size_gb = size / (1024**3)
                    used_gb = used / (1024**3)
                    free_gb = free / (1024**3)
                    
                    # Calculate percentage correctly
                    if size > 0:
                        used_percent = (used / size * 100)
                        free_percent = (free / size * 100)
                    else:
                        used_percent = 0
                        free_percent = 0
                    
                    print(f"📁 Drive: {drive} ({volume_name})")
                    print(f"   💿 Total Size: {size_gb:.2f} GB")
                    print(f"   📊 Used Space: {used_gb:.2f} GB ({used_percent:.1f}%)")
                    print(f"   💚 Free Space: {free_gb:.2f} GB ({free_percent:.1f}%)")
                    print()
        
        # Get physical disk information
        print("🔧 Physical Disks:")
        print("="*80)
        result = subprocess.run(['wmic', 'diskdrive', 'get', 'size,model,mediatype'], 
                              capture_output=True, text=True, shell=True)
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines[1:]:
                if line.strip():
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        size = int(parts[0]) if parts[0].isdigit() else 0
                        model = ' '.join(parts[1:-1]) if len(parts) > 2 else "Unknown"
                        media_type = parts[-1] if len(parts) > 2 else "Unknown"
                        
                        if size > 0:
                            size_gb = size / (1024**3)
                            print(f"💽 Model: {model}")
                            print(f"   📏 Size: {size_gb:.2f} GB")
                            print(f"   🔧 Type: {media_type}")
                            print()
    
    except Exception as e:
        print(f"❌ Error: {str(e)}")

def get_storage_info_linux():
    """Get storage information on Linux"""
    try:
        # Get disk usage information
        result = subprocess.run(['df', '-h'], capture_output=True, text=True)
        
        if result.returncode != 0:
            print("❌ Error: Unable to retrieve storage information")
            return
        
        lines = result.stdout.strip().split('\n')
        if len(lines) < 2:
            print("❌ No storage devices found")
            return
        
        print("💾 Storage Devices:")
        print("="*80)
        
        # Skip header line
        for line in lines[1:]:
            if line.strip():
                parts = line.split()
                if len(parts) >= 6:
                    filesystem = parts[0]
                    size = parts[1]
                    used = parts[2]
                    available = parts[3]
                    use_percent = parts[4]
                    mount_point = parts[5]
                    
                    print(f"📁 Mount Point: {mount_point}")
                    print(f"   💿 Filesystem: {filesystem}")
                    print(f"   📏 Total Size: {size}")
                    print(f"   📊 Used Space: {used} ({use_percent})")
                    print(f"   💚 Free Space: {available}")
                    print()
        
        # Get disk information
        print("🔧 Physical Disks:")
        print("="*80)
        result = subprocess.run(['lsblk', '-d', '-o', 'NAME,SIZE,TYPE,VENDOR,MODEL'], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines[1:]:  # Skip header
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        name = parts[0]
                        size = parts[1] if len(parts) > 1 else "Unknown"
                        disk_type = parts[2] if len(parts) > 2 else "Unknown"
                        vendor = parts[3] if len(parts) > 3 else "Unknown"
                        model = ' '.join(parts[4:]) if len(parts) > 4 else "Unknown"
                        
                        print(f"💽 Device: {name}")
                        print(f"   📏 Size: {size}")
                        print(f"   🔧 Type: {disk_type}")
                        print(f"   🏭 Vendor: {vendor}")
                        print(f"   📝 Model: {model}")
                        print()
    
    except Exception as e:
        print(f"❌ Error: {str(e)}")

def get_storage_info_macos():
    """Get storage information on macOS"""
    try:
        # Get disk usage information
        result = subprocess.run(['df', '-h'], capture_output=True, text=True)
        
        if result.returncode != 0:
            print("❌ Error: Unable to retrieve storage information")
            return
        
        lines = result.stdout.strip().split('\n')
        if len(lines) < 2:
            print("❌ No storage devices found")
            return
        
        print("💾 Storage Devices:")
        print("="*80)
        
        # Skip header line
        for line in lines[1:]:
            if line.strip():
                parts = line.split()
                if len(parts) >= 6:
                    filesystem = parts[0]
                    size = parts[1]
                    used = parts[2]
                    available = parts[3]
                    use_percent = parts[4]
                    mount_point = parts[5]
                    
                    print(f"📁 Mount Point: {mount_point}")
                    print(f"   💿 Filesystem: {filesystem}")
                    print(f"   📏 Total Size: {size}")
                    print(f"   📊 Used Space: {used} ({use_percent})")
                    print(f"   💚 Free Space: {available}")
                    print()
        
        # Get disk information using system_profiler
        print("🔧 Physical Disks:")
        print("="*80)
        result = subprocess.run(['system_profiler', 'SPStorageDataType'], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            current_disk = None
            
            for line in lines:
                line = line.strip()
                if line.startswith('Media Name:'):
                    current_disk = line.split(':', 1)[1].strip()
                    print(f"💽 Disk: {current_disk}")
                elif line.startswith('Capacity:') and current_disk:
                    capacity = line.split(':', 1)[1].strip()
                    print(f"   📏 Capacity: {capacity}")
                elif line.startswith('Protocol:') and current_disk:
                    protocol = line.split(':', 1)[1].strip()
                    print(f"   🔧 Protocol: {protocol}")
                    print()
                    current_disk = None
    
    except Exception as e:
        print(f"❌ Error: {str(e)}")

def get_service_info(port):
    """Get service information for a port"""
    port = int(port)
    services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle DB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        5901: "VNC-1",
        5902: "VNC-2",
        5903: "VNC-3",
        5904: "VNC-4",
        5905: "VNC-5",
        5906: "VNC-6",
        5907: "VNC-7",
        5908: "VNC-8",
        5909: "VNC-9",
        5984: "CouchDB",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        9000: "Webmin",
        9090: "Webmin-Alt",
        27017: "MongoDB",
        27018: "MongoDB-Shard",
        27019: "MongoDB-Config"
    }
    return services.get(port, "Unknown")

def check_suspicious_remote_access(connections):
    """Check for suspicious remote access services"""
    suspicious_services = []
    remote_access_ports = {
        22: "SSH",
        23: "Telnet", 
        3389: "RDP",
        5900: "VNC",
        5901: "VNC-1",
        5902: "VNC-2",
        5903: "VNC-3",
        5904: "VNC-4",
        5905: "VNC-5",
        5906: "VNC-6",
        5907: "VNC-7",
        5908: "VNC-8",
        5909: "VNC-9",
        9000: "Webmin",
        9090: "Webmin-Alt",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt"
    }
    
    for conn in connections:
        local_port = int(conn['local'].split(':')[-1])
        if local_port in remote_access_ports:
            service_name = remote_access_ports[local_port]
            if service_name not in suspicious_services:
                suspicious_services.append(service_name)
    
    return suspicious_services

def check_connections():
    """Check connections to this device"""
    print("🔗 Checking Connections To This Device...")
    print()
    
    system = platform.system()
    
    if system == "Windows":
        check_connections_windows()
    elif system == "Linux":
        check_connections_linux()
    elif system == "Darwin":  # macOS
        check_connections_macos()
    else:
        print(f"❌ Unsupported operating system: {system}")

def check_connections_windows():
    """Check connections on Windows"""
    try:
        # Get active connections using netstat
        result = subprocess.run(['netstat', '-n'], capture_output=True, text=True, shell=True)
        
        if result.returncode != 0:
            print("❌ Error: Unable to retrieve connection information")
            return
        
        lines = result.stdout.strip().split('\n')
        connections = []
        
        # Parse netstat output
        for line in lines:
            if line.strip() and 'TCP' in line:
                parts = line.split()
                if len(parts) >= 4:
                    protocol = parts[0]
                    local_address = parts[1]
                    foreign_address = parts[2]
                    state = parts[3] if len(parts) > 3 else "UNKNOWN"
                    
                    # Only show established connections
                    if state == "ESTABLISHED":
                        connections.append({
                            'protocol': protocol,
                            'local': local_address,
                            'foreign': foreign_address,
                            'state': state
                        })
        
        if not connections:
            print("📊 No active connections found")
            return
        
        print(f"📊 Found {len(connections)} active connections:")
        print("="*80)
        
        # Group connections by foreign IP
        ip_connections = {}
        for conn in connections:
            foreign_ip = conn['foreign'].split(':')[0]
            if foreign_ip not in ip_connections:
                ip_connections[foreign_ip] = []
            ip_connections[foreign_ip].append(conn)
        
        # Display connections grouped by IP
        for foreign_ip, conns in ip_connections.items():
            print(f"🌐 Device IP: {foreign_ip}")
            print(f"   📡 Active Connections: {len(conns)}")
            
            # Show port information with service identification
            ports = set()
            for conn in conns:
                local_port = conn['local'].split(':')[-1]
                foreign_port = conn['foreign'].split(':')[-1]
                service_info = get_service_info(local_port)
                ports.add(f"{local_port} ← {foreign_port} ({service_info})")
            
            for port_info in sorted(ports):
                print(f"   🔌 Port: {port_info}")
            
            # Try to resolve hostname
            try:
                hostname = socket.gethostbyaddr(foreign_ip)[0]
                print(f"   📝 Hostname: {hostname}")
            except:
                print(f"   📝 Hostname: Unknown")
            
            # Check for suspicious remote access patterns
            suspicious_services = check_suspicious_remote_access(conns)
            if suspicious_services:
                print(f"   ⚠️  Remote Access Services: {', '.join(suspicious_services)}")
            
            print()
        
        # Show summary
        unique_ips = len(ip_connections)
        total_connections = len(connections)
        print(f"📈 Summary: {unique_ips} unique devices connected with {total_connections} total connections")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")

def check_connections_linux():
    """Check connections on Linux"""
    try:
        # Get active connections using netstat
        result = subprocess.run(['netstat', '-tn'], capture_output=True, text=True)
        
        if result.returncode != 0:
            print("❌ Error: Unable to retrieve connection information")
            return
        
        lines = result.stdout.strip().split('\n')
        connections = []
        
        # Parse netstat output
        for line in lines:
            if line.strip() and 'tcp' in line:
                parts = line.split()
                if len(parts) >= 4:
                    protocol = parts[0]
                    local_address = parts[3]
                    foreign_address = parts[4]
                    state = parts[5] if len(parts) > 5 else "UNKNOWN"
                    
                    # Only show established connections
                    if state == "ESTABLISHED":
                        connections.append({
                            'protocol': protocol,
                            'local': local_address,
                            'foreign': foreign_address,
                            'state': state
                        })
        
        if not connections:
            print("📊 No active connections found")
            return
        
        print(f"📊 Found {len(connections)} active connections:")
        print("="*80)
        
        # Group connections by foreign IP
        ip_connections = {}
        for conn in connections:
            foreign_ip = conn['foreign'].split(':')[0]
            if foreign_ip not in ip_connections:
                ip_connections[foreign_ip] = []
            ip_connections[foreign_ip].append(conn)
        
        # Display connections grouped by IP
        for foreign_ip, conns in ip_connections.items():
            print(f"🌐 Device IP: {foreign_ip}")
            print(f"   📡 Active Connections: {len(conns)}")
            
            # Show port information with service identification
            ports = set()
            for conn in conns:
                local_port = conn['local'].split(':')[-1]
                foreign_port = conn['foreign'].split(':')[-1]
                service_info = get_service_info(local_port)
                ports.add(f"{local_port} ← {foreign_port} ({service_info})")
            
            for port_info in sorted(ports):
                print(f"   🔌 Port: {port_info}")
            
            # Try to resolve hostname
            try:
                hostname = socket.gethostbyaddr(foreign_ip)[0]
                print(f"   📝 Hostname: {hostname}")
            except:
                print(f"   📝 Hostname: Unknown")
            
            # Check for suspicious remote access patterns
            suspicious_services = check_suspicious_remote_access(conns)
            if suspicious_services:
                print(f"   ⚠️  Remote Access Services: {', '.join(suspicious_services)}")
            
            print()
        
        # Show summary
        unique_ips = len(ip_connections)
        total_connections = len(connections)
        print(f"📈 Summary: {unique_ips} unique devices connected with {total_connections} total connections")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")

def check_connections_macos():
    """Check connections on macOS"""
    try:
        # Get active connections using netstat
        result = subprocess.run(['netstat', '-tn'], capture_output=True, text=True)
        
        if result.returncode != 0:
            print("❌ Error: Unable to retrieve connection information")
            return
        
        lines = result.stdout.strip().split('\n')
        connections = []
        
        # Parse netstat output
        for line in lines:
            if line.strip() and 'tcp' in line:
                parts = line.split()
                if len(parts) >= 4:
                    protocol = parts[0]
                    local_address = parts[3]
                    foreign_address = parts[4]
                    state = parts[5] if len(parts) > 5 else "UNKNOWN"
                    
                    # Only show established connections
                    if state == "ESTABLISHED":
                        connections.append({
                            'protocol': protocol,
                            'local': local_address,
                            'foreign': foreign_address,
                            'state': state
                        })
        
        if not connections:
            print("📊 No active connections found")
            return
        
        print(f"📊 Found {len(connections)} active connections:")
        print("="*80)
        
        # Group connections by foreign IP
        ip_connections = {}
        for conn in connections:
            foreign_ip = conn['foreign'].split(':')[0]
            if foreign_ip not in ip_connections:
                ip_connections[foreign_ip] = []
            ip_connections[foreign_ip].append(conn)
        
        # Display connections grouped by IP
        for foreign_ip, conns in ip_connections.items():
            print(f"🌐 Device IP: {foreign_ip}")
            print(f"   📡 Active Connections: {len(conns)}")
            
            # Show port information with service identification
            ports = set()
            for conn in conns:
                local_port = conn['local'].split(':')[-1]
                foreign_port = conn['foreign'].split(':')[-1]
                service_info = get_service_info(local_port)
                ports.add(f"{local_port} ← {foreign_port} ({service_info})")
            
            for port_info in sorted(ports):
                print(f"   🔌 Port: {port_info}")
            
            # Try to resolve hostname
            try:
                hostname = socket.gethostbyaddr(foreign_ip)[0]
                print(f"   📝 Hostname: {hostname}")
            except:
                print(f"   📝 Hostname: Unknown")
            
            # Check for suspicious remote access patterns
            suspicious_services = check_suspicious_remote_access(conns)
            if suspicious_services:
                print(f"   ⚠️  Remote Access Services: {', '.join(suspicious_services)}")
            
            print()
        
        # Show summary
        unique_ips = len(ip_connections)
        total_connections = len(connections)
        print(f"📈 Summary: {unique_ips} unique devices connected with {total_connections} total connections")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")

def get_device_profiles():
    """Get device profiles including remote connections and local users"""
    print("🔍 Gathering Device Profile Information...")
    print()
    
    if platform.system() == "Windows":
        get_device_profiles_windows()
    elif platform.system() == "Linux":
        get_device_profiles_linux()
    elif platform.system() == "Darwin":  # macOS
        get_device_profiles_macos()
    else:
        print("❌ Unsupported operating system")

def get_device_profiles_windows():
    """Get device profiles on Windows"""
    print("📊 Device Profile Information:")
    print("="*60)
    
    # Get local user accounts
    print("👥 Local User Accounts:")
    print("-" * 30)
    try:
        result = subprocess.run(['wmic', 'useraccount', 'get', 'name,description,disabled'], 
                              capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                for line in lines[1:]:  # Skip header
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            username = parts[0]
                            disabled = "Disabled" if len(parts) > 2 and parts[-1] == "TRUE" else "Active"
                            print(f"   👤 {username} ({disabled})")
            else:
                print("   No local users found")
        else:
            print("   Unable to retrieve user accounts")
    except Exception as e:
        print(f"   Error: {str(e)}")
    
    print()
    
    # Get SSH profiles (if OpenSSH is installed)
    print("🔐 SSH Profiles:")
    print("-" * 30)
    try:
        # Check if OpenSSH is installed
        ssh_result = subprocess.run(['ssh', '-V'], capture_output=True, text=True, shell=True)
        if ssh_result.returncode == 0:
            print("   ✅ OpenSSH is installed")
            
            # Check for SSH config
            ssh_config_path = os.path.expanduser("~/.ssh/config")
            if os.path.exists(ssh_config_path):
                print(f"   📁 SSH Config found: {ssh_config_path}")
                try:
                    with open(ssh_config_path, 'r') as f:
                        config_content = f.read()
                        # Look for Host entries
                        hosts = re.findall(r'Host\s+(\S+)', config_content)
                        if hosts:
                            print("   🔗 Configured SSH hosts:")
                            for host in hosts:
                                print(f"      • {host}")
                        else:
                            print("   No SSH hosts configured")
                except Exception as e:
                    print(f"   Error reading SSH config: {str(e)}")
            else:
                print("   No SSH config file found")
        else:
            print("   ❌ OpenSSH not installed")
    except Exception as e:
        print(f"   Error checking SSH: {str(e)}")
    
    print()
    
    # Get RDP settings
    print("🖥️  Remote Desktop (RDP) Settings:")
    print("-" * 30)
    try:
        # Check if RDP is enabled
        rdp_result = subprocess.run(['reg', 'query', 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server', '/v', 'fDenyTSConnections'], 
                                  capture_output=True, text=True, shell=True)
        if rdp_result.returncode == 0:
            if "0x0" in rdp_result.stdout:
                print("   ✅ RDP is enabled")
            else:
                print("   ❌ RDP is disabled")
        else:
            print("   Unable to check RDP status")
    except Exception as e:
        print(f"   Error checking RDP: {str(e)}")
    
    print()
    
    # Get VPN profiles
    print("🌐 VPN Profiles:")
    print("-" * 30)
    try:
        vpn_result = subprocess.run(['netsh', 'ras', 'show', 'user'], 
                                  capture_output=True, text=True, shell=True)
        if vpn_result.returncode == 0 and vpn_result.stdout.strip():
            print("   VPN users found:")
            lines = vpn_result.stdout.strip().split('\n')
            for line in lines:
                if line.strip() and not line.startswith('User'):
                    print(f"      • {line.strip()}")
        else:
            print("   No VPN users found")
    except Exception as e:
        print(f"   Error checking VPN: {str(e)}")
    
    print("="*60)

def get_device_profiles_linux():
    """Get device profiles on Linux"""
    print("📊 Device Profile Information:")
    print("="*60)
    
    # Get local user accounts
    print("👥 Local User Accounts:")
    print("-" * 30)
    try:
        result = subprocess.run(['cat', '/etc/passwd'], capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            user_count = 0
            for line in lines:
                if line.strip() and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 3:
                        username = parts[0]
                        uid = parts[2]
                        shell = parts[6] if len(parts) > 6 else ""
                        
                        # Only show regular users (UID >= 1000) and not system users
                        if uid.isdigit() and int(uid) >= 1000:
                            user_type = "Regular User"
                            if shell == "/bin/bash" or shell == "/bin/sh":
                                user_type += " (Shell Access)"
                            print(f"   👤 {username} (UID: {uid}) - {user_type}")
                            user_count += 1
            
            if user_count == 0:
                print("   No regular users found")
        else:
            print("   Unable to retrieve user accounts")
    except Exception as e:
        print(f"   Error: {str(e)}")
    
    print()
    
    # Get SSH profiles
    print("🔐 SSH Profiles:")
    print("-" * 30)
    try:
        # Check if SSH is installed
        ssh_result = subprocess.run(['which', 'ssh'], capture_output=True, text=True)
        if ssh_result.returncode == 0:
            print("   ✅ SSH is installed")
            
            # Check SSH service status
            ssh_service = subprocess.run(['systemctl', 'is-active', 'ssh'], capture_output=True, text=True)
            if ssh_service.returncode == 0:
                status = ssh_service.stdout.strip()
                if status == "active":
                    print("   🟢 SSH service is running")
                else:
                    print(f"   🔴 SSH service status: {status}")
            
            # Check for SSH config
            ssh_config_path = os.path.expanduser("~/.ssh/config")
            if os.path.exists(ssh_config_path):
                print(f"   📁 SSH Config found: {ssh_config_path}")
                try:
                    with open(ssh_config_path, 'r') as f:
                        config_content = f.read()
                        hosts = re.findall(r'Host\s+(\S+)', config_content)
                        if hosts:
                            print("   🔗 Configured SSH hosts:")
                            for host in hosts:
                                print(f"      • {host}")
                        else:
                            print("   No SSH hosts configured")
                except Exception as e:
                    print(f"   Error reading SSH config: {str(e)}")
            else:
                print("   No SSH config file found")
        else:
            print("   ❌ SSH not installed")
    except Exception as e:
        print(f"   Error checking SSH: {str(e)}")
    
    print()
    
    # Get VPN profiles
    print("🌐 VPN Profiles:")
    print("-" * 30)
    try:
        # Check for common VPN configurations
        vpn_configs = [
            "/etc/openvpn",
            "/etc/ppp/peers",
            "/etc/NetworkManager/system-connections"
        ]
        
        vpn_found = False
        for config_path in vpn_configs:
            if os.path.exists(config_path):
                print(f"   📁 VPN config directory: {config_path}")
                try:
                    files = os.listdir(config_path)
                    if files:
                        print("   📄 VPN configuration files:")
                        for file in files[:5]:  # Show first 5 files
                            print(f"      • {file}")
                        if len(files) > 5:
                            print(f"      ... and {len(files) - 5} more")
                    vpn_found = True
                except Exception as e:
                    print(f"   Error reading {config_path}: {str(e)}")
        
        if not vpn_found:
            print("   No VPN configurations found")
    except Exception as e:
        print(f"   Error checking VPN: {str(e)}")
    
    print("="*60)

def get_device_profiles_macos():
    """Get device profiles on macOS"""
    print("📊 Device Profile Information:")
    print("="*60)
    
    # Get local user accounts
    print("👥 Local User Accounts:")
    print("-" * 30)
    try:
        result = subprocess.run(['dscl', '.', 'list', '/Users'], capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            user_count = 0
            for username in lines:
                if username.strip() and not username.startswith('_') and username != 'daemon' and username != 'nobody':
                    try:
                        # Get user details
                        uid_result = subprocess.run(['dscl', '.', 'read', f'/Users/{username}', 'UniqueID'], 
                                                  capture_output=True, text=True)
                        if uid_result.returncode == 0:
                            uid_match = re.search(r'UniqueID:\s*(\d+)', uid_result.stdout)
                            if uid_match:
                                uid = uid_match.group(1)
                                if int(uid) >= 500:  # Regular users on macOS
                                    print(f"   👤 {username} (UID: {uid})")
                                    user_count += 1
                    except:
                        continue
            
            if user_count == 0:
                print("   No regular users found")
        else:
            print("   Unable to retrieve user accounts")
    except Exception as e:
        print(f"   Error: {str(e)}")
    
    print()
    
    # Get SSH profiles
    print("🔐 SSH Profiles:")
    print("-" * 30)
    try:
        # Check if SSH is enabled
        ssh_result = subprocess.run(['sudo', 'systemsetup', '-getremotelogin'], capture_output=True, text=True)
        if ssh_result.returncode == 0:
            if "On" in ssh_result.stdout:
                print("   ✅ SSH is enabled")
            else:
                print("   ❌ SSH is disabled")
        else:
            print("   Unable to check SSH status")
        
        # Check for SSH config
        ssh_config_path = os.path.expanduser("~/.ssh/config")
        if os.path.exists(ssh_config_path):
            print(f"   📁 SSH Config found: {ssh_config_path}")
            try:
                with open(ssh_config_path, 'r') as f:
                    config_content = f.read()
                    hosts = re.findall(r'Host\s+(\S+)', config_content)
                    if hosts:
                        print("   🔗 Configured SSH hosts:")
                        for host in hosts:
                            print(f"      • {host}")
                    else:
                        print("   No SSH hosts configured")
            except Exception as e:
                print(f"   Error reading SSH config: {str(e)}")
        else:
            print("   No SSH config file found")
    except Exception as e:
        print(f"   Error checking SSH: {str(e)}")
    
    print()
    
    # Get VPN profiles
    print("🌐 VPN Profiles:")
    print("-" * 30)
    try:
        # Check for VPN configurations in Network preferences
        vpn_configs = [
            "/Library/Preferences/SystemConfiguration/com.apple.network.identification.plist",
            os.path.expanduser("~/Library/Preferences/ByHost/com.apple.network.identification.*.plist")
        ]
        
        vpn_found = False
        for config_path in vpn_configs:
            if os.path.exists(config_path) or '*' in config_path:
                print(f"   📁 VPN config location: {config_path}")
                vpn_found = True
        
        # Check for VPN services
        vpn_services = subprocess.run(['scutil', '--nc', 'list'], capture_output=True, text=True)
        if vpn_services.returncode == 0 and vpn_services.stdout.strip():
            print("   📄 VPN services:")
            lines = vpn_services.stdout.strip().split('\n')
            for line in lines:
                if line.strip() and not line.startswith('Connected'):
                    print(f"      • {line.strip()}")
            vpn_found = True
        
        if not vpn_found:
            print("   No VPN configurations found")
    except Exception as e:
        print(f"   Error checking VPN: {str(e)}")
    
    print("="*60)

def show_menu():
    """Display the main menu"""
    print("📋 Available Options:")
    print("="*30)
    print("1. 🔍 Get Fingerprint Info")
    print("2. 📡 Get Past WiFi Passwords")
    print("3. 💾 Storage Info")
    print("4. 🔗 Check Connections To This Device")
    print("5. 🔓 Get Device Profiles")
    print("6. 🚪 Exit")
    print("="*30)

def main():
    """Main function"""
    color = set_random_color()
    
    # Check if running with admin privileges
    if platform.system() == "Windows":
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.getuid() == 0
    
    if not is_admin:
        print("⚠️  Some features may require elevated privileges")
        print()
    
    while True:
        print_banner()
        show_menu()
        
        try:
            choice = input("🔢 Enter your choice (1-6): ").strip()
            
            if choice == '1':
                print()
                get_fingerprint_info()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '2':
                print()
                get_wifi_passwords()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '3':
                print()
                get_storage_info()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '4':
                print()
                check_connections()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '5':
                print()
                get_device_profiles()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '6':
                print("👋 Thank you for using GeckoDevice!")
                reset_color()
                break
            
            else:
                print("⚠️  Invalid choice. Please enter 1, 2, 3, 4, 5, or 6.")
                time.sleep(2)
                os.system('cls' if platform.system() == "Windows" else 'clear')
        
        except KeyboardInterrupt:
            print("\n👋 Thank you for using GeckoDevice!")
            reset_color()
            break
        except Exception as e:
            print(f"❌ An error occurred: {str(e)}")
            time.sleep(2)
            os.system('cls' if platform.system() == "Windows" else 'clear')

if __name__ == "__main__":
    main() 