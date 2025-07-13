
import subprocess
import platform
import socket
import threading
import time
import ipaddress
import concurrent.futures
import os
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
    if platform.system() == "Windows":
        os.system('color 07')
    else:
        print('\033[0m', end='')

def run_command(command, shell=True):
    """Run a command and return success status and output"""
    try:
        result = subprocess.run(command, shell=shell, capture_output=True, text=True, timeout=10)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)

def get_local_ip():
    """Get the local machine's IP address"""
    try:
        # Connect to a remote address to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        return local_ip
    except Exception:
        return "127.0.0.1"

def get_network_range(local_ip):
    """Get the network range based on local IP"""
    try:
        # Get network interface info
        if platform.system() == "Windows":
            success, stdout, stderr = run_command('ipconfig | findstr "IPv4"')
            if success:
                lines = stdout.strip().split('\n')
                for line in lines:
                    if local_ip in line:
                        # Extract subnet mask from ipconfig output
                        success2, stdout2, stderr2 = run_command('ipconfig | findstr "Subnet Mask"')
                        if success2:
                            subnet_lines = stdout2.strip().split('\n')
                            # Find corresponding subnet mask
                            for i, subnet_line in enumerate(subnet_lines):
                                if i < len(lines):
                                    subnet_mask = subnet_line.split(':')[-1].strip()
                                    if subnet_mask:
                                        # Create network object
                                        network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)
                                        return str(network.network_address), str(network.broadcast_address)
        else:
            # Linux/Mac approach
            success, stdout, stderr = run_command('ip route | grep default')
            if success:
                # Parse network from route
                parts = stdout.strip().split()
                if len(parts) >= 3:
                    network = parts[2]
                    return network, None
        
        # Fallback: assume /24 network
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network.network_address), str(network.broadcast_address)
        
    except Exception as e:
        print(f"⚠️  Error getting network range: {e}")
        # Fallback to /24 network
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network.network_address), str(network.broadcast_address)

def ping_host(ip):
    """Ping a single host to check if it's alive"""
    try:
        if platform.system() == "Windows":
            success, stdout, stderr = run_command(f'ping -n 1 -w 1000 {ip}')
        else:
            success, stdout, stderr = run_command(f'ping -c 1 -W 1 {ip}')
        
        return success, stdout
    except Exception:
        return False, ""

def resolve_hostname(ip):
    """Try to resolve hostname for an IP address"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return None
    except Exception:
        return None

def get_local_mac_address():
    """Get the local machine's MAC address"""
    try:
        if platform.system() == "Windows":
            success, stdout, stderr = run_command('ipconfig /all')
            if success and stdout.strip():
                lines = stdout.strip().split('\n')
                current_adapter = None
                for line in lines:
                    line = line.strip()
                    if 'adapter' in line.lower() and ':' in line:
                        current_adapter = line.split(':')[0].strip()
                    elif current_adapter and 'physical address' in line.lower():
                        mac = line.split(':')[-1].strip()
                        if mac and len(mac) == 17:
                            return mac
        else:
            # Linux/Mac approach
            success, stdout, stderr = run_command('ifconfig')
            if success and stdout.strip():
                lines = stdout.strip().split('\n')
                for line in lines:
                    if 'ether' in line:
                        mac = line.split('ether')[-1].strip()
                        if mac and len(mac) == 17:
                            return mac
    except Exception:
        pass
    return None

def get_mac_address(ip):
    """Get MAC address for an IP (cross-platform)"""
    try:
        if platform.system() == "Windows":
            # First try to get from ARP table
            success, stdout, stderr = run_command(f'arp -a {ip}')
            if success and stdout.strip():
                lines = stdout.strip().split('\n')
                for line in lines:
                    if ip in line:
                        # Look for MAC address pattern (xx-xx-xx-xx-xx-xx or xx:xx:xx:xx:xx:xx)
                        import re
                        mac_pattern = r'([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}'
                        mac_match = re.search(mac_pattern, line)
                        if mac_match:
                            return mac_match.group(0)
            
            # If not found in ARP, try to ping first to populate ARP table
            if ip != get_local_ip():  # Don't ping ourselves
                run_command(f'ping -n 1 -w 1000 {ip}')
                success, stdout, stderr = run_command(f'arp -a {ip}')
                if success and stdout.strip():
                    lines = stdout.strip().split('\n')
                    for line in lines:
                        if ip in line:
                            import re
                            mac_pattern = r'([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}'
                            mac_match = re.search(mac_pattern, line)
                            if mac_match:
                                return mac_match.group(0)
        else:
            # Linux/Mac approach
            success, stdout, stderr = run_command(f'arp -n {ip}')
            if success and stdout.strip():
                lines = stdout.strip().split('\n')
                for line in lines:
                    if ip in line:
                        import re
                        mac_pattern = r'([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}'
                        mac_match = re.search(mac_pattern, line)
                        if mac_match:
                            return mac_match.group(0)
    except Exception:
        pass
    return None

def get_public_ip():
    """Get the public IP address of the current machine"""
    try:
        # Try multiple services for redundancy
        services = [
            'https://api.ipify.org',
            'https://ifconfig.me',
            'https://icanhazip.com',
            'https://ident.me'
        ]
        
        for service in services:
            try:
                import urllib.request
                with urllib.request.urlopen(service, timeout=5) as response:
                    public_ip = response.read().decode('utf-8').strip()
                    if public_ip and '.' in public_ip:
                        return public_ip
            except Exception:
                continue
    except Exception:
        pass
    return None

def get_device_vendor(mac_address):
    """Get device vendor from MAC address (basic OUI lookup)"""
    if not mac_address:
        return None
    
    try:
        # Extract OUI (first 6 characters) from MAC
        oui = mac_address.replace(':', '').replace('-', '')[:6].upper()
        
        # Common vendor OUIs (this is a small subset - in a real app you'd use a database)
        vendors = {
            '000C29': 'VMware',
            '001A11': 'Google',
            '002272': 'American Micro-Fuel Device Corp',
            '00AABB': 'Shenzhen',
            '00B0D0': 'Next Level Communications',
            '00C04F': '3Com',
            '00D0B7': 'Intel',
            '00E018': 'Cisco',
            '080027': 'PCS Systemtechnik GmbH',
            '080069': 'Silicon Graphics',
            '080086': 'Imagen/QMS',
            '080089': 'Kinetics',
            '08008A': 'Pyramid Technology',
            '08008B': 'Network Research',
            '08008C': 'Xerox',
            '08008D': 'Digital Equipment',
            '08008E': 'Bull',
            '08008F': 'Spider Systems',
            '080090': 'Orcatech',
            '080091': 'Torus Systems',
            '080092': 'Seiko Systems',
            '080093': 'Acorn',
            '080094': 'Compatible',
            '080095': 'Network General',
            '080096': 'Network Computing Devices',
            '080097': 'Stratus',
            '080098': 'Network Systems',
            '080099': 'Xerox',
            '08009A': 'Logicraft',
            '08009B': 'Network Computing Devices',
            '08009C': 'AT&T',
            '08009D': 'Crystal Semiconductor',
            '08009E': 'Chipcom',
            '08009F': 'Synernetics',
            '0800A0': 'Plexcom',
            '0800A1': 'AST Research',
            '0800A2': 'Mitsubishi Electric',
            '0800A3': 'Eon Systems',
            '0800A4': 'Arix',
            '0800A5': 'Artel Communications',
            '0800A6': 'FiberCom',
            '0800A7': 'Networth',
            '0800A8': 'Systech',
            '0800A9': 'Compatible',
            '0800AA': 'Network Computing Devices',
            '0800AB': 'Advanced Micro Devices',
            '0800AC': 'Atheros Communications',
            '0800AD': 'Sony',
            '0800AE': 'Seagate Technology',
            '0800AF': 'Western Digital',
            '0800B0': 'Maxtor',
            '0800B1': 'Hewlett-Packard',
            '0800B2': 'IBM',
            '0800B3': 'Apple',
            '0800B4': 'Dell',
            '0800B5': 'Gateway',
            '0800B6': 'Compaq',
            '0800B7': 'Toshiba',
            '0800B8': 'Samsung',
            '0800B9': 'LG Electronics',
            '0800BA': 'Panasonic',
            '0800BB': 'Sharp',
            '0800BC': 'Canon',
            '0800BD': 'Epson',
            '0800BE': 'Brother',
            '0800BF': 'Lexmark',
            '0800C0': 'Ricoh',
            '0800C1': 'Xerox',
            '0800C2': 'HP',
            '0800C3': 'Canon',
            '0800C4': 'Epson',
            '0800C5': 'Brother',
            '0800C6': 'Lexmark',
            '0800C7': 'Ricoh',
            '0800C8': 'Xerox',
            '0800C9': 'HP',
            '0800CA': 'Canon',
            '0800CB': 'Epson',
            '0800CC': 'Brother',
            '0800CD': 'Lexmark',
            '0800CE': 'Ricoh',
            '0800CF': 'Xerox',
            '0800D0': 'HP',
            '0800D1': 'Canon',
            '0800D2': 'Epson',
            '0800D3': 'Brother',
            '0800D4': 'Lexmark',
            '0800D5': 'Ricoh',
            '0800D6': 'Xerox',
            '0800D7': 'HP',
            '0800D8': 'Canon',
            '0800D9': 'Epson',
            '0800DA': 'Brother',
            '0800DB': 'Lexmark',
            '0800DC': 'Ricoh',
            '0800DD': 'Xerox',
            '0800DE': 'HP',
            '0800DF': 'Canon',
            '0800E0': 'Epson',
            '0800E1': 'Brother',
            '0800E2': 'Lexmark',
            '0800E3': 'Ricoh',
            '0800E4': 'Xerox',
            '0800E5': 'HP',
            '0800E6': 'Canon',
            '0800E7': 'Epson',
            '0800E8': 'Brother',
            '0800E9': 'Lexmark',
            '0800EA': 'Ricoh',
            '0800EB': 'Xerox',
            '0800EC': 'HP',
            '0800ED': 'Canon',
            '0800EE': 'Epson',
            '0800EF': 'Brother',
            '0800F0': 'Lexmark',
            '0800F1': 'Ricoh',
            '0800F2': 'Xerox',
            '0800F3': 'HP',
            '0800F4': 'Canon',
            '0800F5': 'Epson',
            '0800F6': 'Brother',
            '0800F7': 'Lexmark',
            '0800F8': 'Ricoh',
            '0800F9': 'Xerox',
            '0800FA': 'HP',
            '0800FB': 'Canon',
            '0800FC': 'Epson',
            '0800FD': 'Brother',
            '0800FE': 'Lexmark',
            '0800FF': 'Ricoh'
        }
        
        return vendors.get(oui, 'Unknown Vendor')
    except Exception:
        return None

def get_network_interface_info():
    """Get detailed network interface information"""
    interfaces = {}
    
    try:
        if platform.system() == "Windows":
            success, stdout, stderr = run_command('ipconfig /all')
            if success:
                lines = stdout.strip().split('\n')
                current_adapter = None
                
                for line in lines:
                    line = line.strip()
                    if 'adapter' in line.lower() and ':' in line:
                        current_adapter = line.split(':')[0].strip()
                        interfaces[current_adapter] = {'name': current_adapter}
                    elif current_adapter and 'physical address' in line.lower():
                        mac = line.split(':')[-1].strip()
                        if mac and len(mac) == 17:
                            interfaces[current_adapter]['mac'] = mac
                    elif current_adapter and 'ipv4 address' in line.lower():
                        ip = line.split(':')[-1].strip()
                        if ip and '.' in ip:
                            interfaces[current_adapter]['ip'] = ip
        else:
            # Linux/Mac approach
            success, stdout, stderr = run_command('ifconfig')
            if success:
                lines = stdout.strip().split('\n')
                current_adapter = None
                
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith(' '):
                        current_adapter = line.split(':')[0]
                        interfaces[current_adapter] = {'name': current_adapter}
                    elif current_adapter and 'ether' in line:
                        mac = line.split('ether')[-1].strip()
                        if mac and len(mac) == 17:
                            interfaces[current_adapter]['mac'] = mac
                    elif current_adapter and 'inet ' in line:
                        ip = line.split('inet ')[-1].split()[0]
                        if ip and '.' in ip:
                            interfaces[current_adapter]['ip'] = ip
    except Exception:
        pass
    
    return interfaces

def scan_network():
    """Scan the entire network for active hosts"""
    print("🔍 Starting network scan...")
    print("="*60)
    
    # Get local IP and network range
    local_ip = get_local_ip()
    print(f"🏠 Local IP: {local_ip}")
    
    network_start, network_end = get_network_range(local_ip)
    print(f"🌐 Network range: {network_start} to {network_end}")
    
    # Generate list of IPs to scan
    try:
        if network_end:
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
        else:
            # Fallback to /24 network
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
    except Exception as e:
        print(f"❌ Error generating IP list: {e}")
        return []
    
    # Filter out ignored IPs
    ip_list = filter_ignored_ips(ip_list)
    
    print(f"📡 Scanning {len(ip_list)} IP addresses...")
    print("⏳ This may take a few minutes...")
    print()
    
    # Scan with progress indicator
    active_hosts = []
    total_ips = len(ip_list)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        # Submit all ping tasks
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in ip_list}
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            completed += 1
            
            try:
                success, output = future.result()
                if success:
                    active_hosts.append(ip)
                    print(f"✅ Found active host: {ip}")
                
                # Progress indicator
                if completed % 10 == 0:
                    progress = (completed / total_ips) * 100
                    print(f"📊 Progress: {completed}/{total_ips} ({progress:.1f}%)")
                    
            except Exception as e:
                print(f"❌ Error scanning {ip}: {e}")
    
    return active_hosts

def scan_network_with_hostnames():
    """Scan network and only return IPs that have resolvable hostnames"""
    print("🔍 Scanning network for IPs with known hostnames...")
    print("="*60)
    
    # First scan all IPs (already filtered for ignored IPs)
    all_hosts = scan_network()
    
    if not all_hosts:
        print("❌ No active hosts found")
        return []
    
    print("\n🔍 Checking hostnames for all active hosts...")
    hosts_with_names = []
    
    for ip in all_hosts:
        hostname = resolve_hostname(ip)
        if hostname:
            hosts_with_names.append(ip)
            print(f"✅ {ip} -> {hostname}")
        else:
            print(f"❌ {ip} -> No hostname")
    
    print(f"\n📊 Found {len(hosts_with_names)} IPs with hostnames out of {len(all_hosts)} total active hosts")
    return hosts_with_names

def analyze_hosts(active_hosts):
    """Analyze active hosts for detailed information"""
    print("\n" + "="*60)
    print("🔍 ANALYZING ACTIVE HOSTS")
    print("="*60)
    
    if not active_hosts:
        print("❌ No active hosts found on the network")
        return
    
    # Filter out ignored IPs
    active_hosts = filter_ignored_ips(active_hosts)
    
    if not active_hosts:
        print("❌ No active hosts found (all were ignored)")
        return
    
    print(f"📊 Found {len(active_hosts)} active hosts")
    print()
    
    # Get public IP for reference
    public_ip = get_public_ip()
    if public_ip:
        print(f"🌐 Your Public IP: {public_ip}")
        print()
    
    # Get local network interface info
    local_interfaces = get_network_interface_info()
    local_ip = get_local_ip()
    
    # Sort hosts (put local host first)
    active_hosts.sort(key=lambda x: (x != local_ip, x))
    
    for i, ip in enumerate(active_hosts, 1):
        print(f"🔍 Host {i}/{len(active_hosts)}: {ip}")
        
        # Check if this is the local machine
        is_local = ip == local_ip
        if is_local:
            print(f"🏠 Status: THIS IS YOUR MACHINE")
        
        # Resolve hostname
        hostname = resolve_hostname(ip)
        if hostname:
            print(f"📝 Hostname: {hostname}")
        else:
            print(f"📝 Hostname: Unknown")
        
        # Get MAC address and vendor info
        if is_local:
            # Use local MAC address function for our own device
            mac = get_local_mac_address()
        else:
            # Use regular MAC address function for other devices
            mac = get_mac_address(ip)
        
        if mac:
            vendor = get_device_vendor(mac)
            print(f"🔗 MAC Address: {mac}")
            if vendor:
                print(f"🏭 Device Vendor: {vendor}")
        else:
            print(f"🔗 MAC Address: Unknown")
        
        # Show network interface info for local machine
        if is_local and local_interfaces:
            print(f"🔧 Network Interfaces:")
            for adapter_name, info in local_interfaces.items():
                if 'ip' in info and info['ip'] == ip:
                    print(f"   📡 {adapter_name}")
                    if 'mac' in info:
                        print(f"      MAC: {info['mac']}")
        
        # Show IP type (private vs public)
        if ip.startswith(('10.', '192.168.', '172.')):
            print(f"🌐 IP Type: Private (Local Network)")
        elif ip == public_ip:
            print(f"🌐 IP Type: Public (Internet)")
        else:
            print(f"🌐 IP Type: Other")
        
        print("-" * 50)

def check_suspicious_activity():
    """Check for suspicious network activity"""
    print("\n" + "="*60)
    print("🚨 SUSPICIOUS ACTIVITY CHECK")
    print("="*60)
    
    # Check for unusual network connections
    print("🔍 Checking for unusual network connections...")
    
    if platform.system() == "Windows":
        success, stdout, stderr = run_command('netstat -an | findstr "ESTABLISHED"')
        if success:
            connections = stdout.strip().split('\n')
            print(f"📊 Found {len(connections)} active connections")
            
            # Look for suspicious ports
            suspicious_ports = ['22', '23', '3389', '4899', '5631', '5009']
            for connection in connections:
                for port in suspicious_ports:
                    if f":{port} " in connection:
                        print(f"⚠️  Suspicious connection detected: {connection.strip()}")
    else:
        print("🐧 Suspicious activity check not available on this platform")

def get_next_ip_list_number():
    """Get the next available IP list number"""
    import glob
    import os
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pattern = os.path.join(script_dir, "IPList_*.txt")
    existing_files = glob.glob(pattern)
    
    if not existing_files:
        return 1
    
    numbers = []
    for file in existing_files:
        try:
            filename = os.path.basename(file)
            number = int(filename.replace("IPList_", "").replace(".txt", ""))
            numbers.append(number)
        except:
            continue
    
    if not numbers:
        return 1
    
    return max(numbers) + 1

def save_ips_to_file(active_hosts, filename=None):
    """Save IP list to a file"""
    print(f"DEBUG: save_ips_to_file called with {len(active_hosts) if active_hosts else 0} IPs")
    print(f"DEBUG: active_hosts content: {active_hosts}")
    
    if not active_hosts:
        print("❌ No IPs to save - the list is empty")
        return None
    
    if not filename:
        list_number = get_next_ip_list_number()
        filename = f"IPList_{list_number}.txt"
    
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(script_dir, filename)
        print(f"DEBUG: Saving to filepath: {filepath}")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            print("DEBUG: File opened successfully")
            f.write(f"Network IP List - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            print("DEBUG: Wrote header line")
            f.write("="*60 + "\n\n")
            print("DEBUG: Wrote separator line")
            
            # Get public IP for reference
            public_ip = get_public_ip()
            if public_ip:
                f.write(f"Your Public IP: {public_ip}\n\n")
                print("DEBUG: Wrote public IP")
            
            local_ip = get_local_ip()
            f.write(f"Total IPs found: {len(active_hosts)}\n\n")
            print("DEBUG: Wrote total IPs count")
            
            for ip in sorted(active_hosts):
                print(f"DEBUG: Processing IP: {ip}")
                try:
                    hostname = resolve_hostname(ip)
                    print(f"DEBUG: Hostname for {ip}: {hostname}")
                    mac = get_mac_address(ip)
                    print(f"DEBUG: MAC for {ip}: {mac}")
                    vendor = get_device_vendor(mac) if mac else None
                    print(f"DEBUG: Vendor for {ip}: {vendor}")
                    
                    f.write(f"IP: {ip}\n")
                    f.write(f"Hostname: {hostname if hostname else 'Unknown'}\n")
                    f.write(f"MAC: {mac if mac else 'Unknown'}\n")
                    if vendor:
                        f.write(f"Vendor: {vendor}\n")
                    f.write(f"Local: {'Yes' if ip == local_ip else 'No'}\n")
                    
                    # IP type
                    if ip.startswith(('10.', '192.168.', '172.')):
                        f.write(f"IP Type: Private (Local Network)\n")
                    elif ip == public_ip:
                        f.write(f"IP Type: Public (Internet)\n")
                    else:
                        f.write(f"IP Type: Other\n")
                    
                    f.write("-" * 30 + "\n")
                    print(f"DEBUG: Successfully wrote data for {ip}")
                except Exception as e:
                    print(f"DEBUG: Error processing IP {ip}: {e}")
                    # Write basic info even if there's an error
                    f.write(f"IP: {ip}\n")
                    f.write(f"Hostname: Unknown (Error)\n")
                    f.write(f"MAC: Unknown (Error)\n")
                    f.write(f"Local: {'Yes' if ip == local_ip else 'No'}\n")
                    f.write(f"IP Type: Private (Local Network)\n")
                    f.write("-" * 30 + "\n")
        
        print(f"✅ IP list saved to: {filename}")
        print(f"📊 Saved {len(active_hosts)} IPs")
        return filename
    except Exception as e:
        print(f"❌ Error saving IP list: {e}")
        import traceback
        traceback.print_exc()
        return None

def load_ips_from_file(filepath):
    """Load IP list from a file"""
    try:
        ips = []
        with open(filepath, 'r') as f:
            lines = f.readlines()
            
        for line in lines:
            line = line.strip()
            if line.startswith("IP: "):
                ip = line[4:]  # Remove "IP: " prefix
                if ip not in ips:
                    ips.append(ip)
        
        return ips
    except Exception as e:
        print(f"❌ Error loading IP list: {e}")
        return None

def compare_ip_lists(current_ips, previous_ips):
    """Compare current IP list with a previous one"""
    print("\n" + "="*60)
    print("📊 IP LIST COMPARISON")
    print("="*60)
    
    current_set = set(current_ips)
    previous_set = set(previous_ips)
    
    new_ips = current_set - previous_set
    removed_ips = previous_set - current_set
    common_ips = current_set & previous_set
    
    print(f"📊 Current IPs: {len(current_ips)}")
    print(f"📊 Previous IPs: {len(previous_ips)}")
    print(f"📊 Common IPs: {len(common_ips)}")
    print()
    
    if new_ips:
        print("🆕 NEW IPs (not in previous list):")
        for ip in sorted(new_ips):
            hostname = resolve_hostname(ip)
            hostname_str = f" ({hostname})" if hostname else ""
            print(f"   ✅ {ip}{hostname_str}")
        print()
    else:
        print("✅ No new IPs found")
        print()
    
    if removed_ips:
        print("❌ REMOVED IPs (in previous but not current):")
        for ip in sorted(removed_ips):
            print(f"   ❌ {ip}")
        print()
    else:
        print("✅ No IPs were removed")
        print()
    
    if common_ips:
        print("🔄 COMMON IPs (in both lists):")
        for ip in sorted(common_ips):
            hostname = resolve_hostname(ip)
            hostname_str = f" ({hostname})" if hostname else ""
            print(f"   🔄 {ip}{hostname_str}")
    
    # Save comparison results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"ip_comparison_{timestamp}.txt"
    
    try:
        with open(filename, 'w') as f:
            f.write(f"IP List Comparison - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Current IPs: {len(current_ips)}\n")
            f.write(f"Previous IPs: {len(previous_ips)}\n")
            f.write(f"Common IPs: {len(common_ips)}\n\n")
            
            if new_ips:
                f.write("NEW IPs:\n")
                for ip in sorted(new_ips):
                    hostname = resolve_hostname(ip)
                    hostname_str = f" ({hostname})" if hostname else ""
                    f.write(f"   {ip}{hostname_str}\n")
                f.write("\n")
            
            if removed_ips:
                f.write("REMOVED IPs:\n")
                for ip in sorted(removed_ips):
                    f.write(f"   {ip}\n")
                f.write("\n")
        
        print(f"✅ Comparison results saved to: {filename}")
    except Exception as e:
        print(f"❌ Error saving comparison: {e}")

def show_ips_with_names(active_hosts):
    """Show only IPs that have resolvable hostnames"""
    print("\n" + "="*60)
    print("📝 IPs WITH HOSTNAMES")
    print("="*60)
    
    # Filter out ignored IPs
    active_hosts = filter_ignored_ips(active_hosts)
    
    if not active_hosts:
        print("❌ No active hosts found (all were ignored)")
        return
    
    hosts_with_names = []
    
    for ip in active_hosts:
        hostname = resolve_hostname(ip)
        if hostname:
            hosts_with_names.append((ip, hostname))
    
    if hosts_with_names:
        print(f"📊 Found {len(hosts_with_names)} IPs with hostnames:")
        print()
        
        local_ip = get_local_ip()
        public_ip = get_public_ip()
        
        for ip, hostname in sorted(hosts_with_names):
            mac = get_mac_address(ip)
            vendor = get_device_vendor(mac) if mac else None
            
            # Device identification
            device_info = []
            if ip == local_ip:
                device_info.append("🏠 YOUR MACHINE")
            if mac:
                device_info.append(f"MAC: {mac}")
            if vendor:
                device_info.append(f"Vendor: {vendor}")
            
            # IP type
            if ip.startswith(('10.', '192.168.', '172.')):
                device_info.append("Private IP")
            elif ip == public_ip:
                device_info.append("Public IP")
            
            device_str = " | ".join(device_info) if device_info else ""
            print(f"   📡 {ip} -> {hostname}")
            if device_str:
                print(f"      {device_str}")
    else:
        print("❌ No IPs with hostnames found")
        print("💡 This could indicate:")
        print("   - Network devices don't have hostnames")
        print("   - DNS resolution issues")
        print("   - Firewall blocking name resolution")

def scan_ports_for_ip(ip, common_ports=None):
    """Scan common ports for a single IP"""
    if common_ports is None:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 4899, 5631, 5000, 5009, 5357]
    
    open_ports = []
    
    print(f"🔍 Scanning ports for {ip}...")
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                open_ports.append(port)
                print(f"   ✅ Port {port} is open")
        except Exception:
            pass
    
    return open_ports

def get_port_description(port):
    """Get description for a port number"""
    port_descriptions = {
        21: "FTP (File Transfer)",
        22: "SSH (Secure Shell) - REMOTE CONTROL",
        23: "Telnet - REMOTE CONTROL (INSECURE)",
        25: "SMTP (Email)",
        53: "DNS (Domain Name System)",
        80: "HTTP (Web Server)",
        110: "POP3 (Email)",
        135: "RPC (Remote Procedure Call) - REMOTE CONTROL",
        139: "NetBIOS (File Sharing)",
        143: "IMAP (Email)",
        443: "HTTPS (Secure Web)",
        445: "SMB (File Sharing) - REMOTE CONTROL",
        993: "IMAP SSL (Secure Email)",
        995: "POP3 SSL (Secure Email)",
        1433: "SQL Server (Database)",
        1521: "Oracle Database",
        3306: "MySQL Database",
        3389: "RDP (Remote Desktop) - REMOTE CONTROL",
        5432: "PostgreSQL Database",
        5900: "VNC (Remote Desktop) - REMOTE CONTROL",
        6379: "Redis (Database)",
        8080: "HTTP Alternative (Web Server)",
        8443: "HTTPS Alternative (Secure Web)",
        4899: "Radmin (Remote Control) - REMOTE CONTROL",
        5631: "PCAnywhere (Remote Control) - REMOTE CONTROL",
        5000: "Python Flask (Web Server)",
        5009: "Back Orifice (MALWARE) - REMOTE CONTROL",
        5357: "Windows Remote Management"
    }
    
    return port_descriptions.get(port, "Unknown Service")

def scan_all_ips_for_ports(active_hosts):
    """Scan all active IPs for open ports"""
    print("\n" + "="*60)
    print("🔍 SCANNING ALL IPs FOR OPEN PORTS")
    print("="*60)
    
    if not active_hosts:
        print("❌ No active hosts to scan")
        return
    
    # Filter out ignored IPs from the active hosts list
    active_hosts = filter_ignored_ips(active_hosts)
    
    if not active_hosts:
        print("❌ No active hosts to scan (all were ignored)")
        return
    
    scan_results = {}
    suspicious_devices = []
    
    for i, ip in enumerate(active_hosts, 1):
        print(f"\n🔍 Scanning {i}/{len(active_hosts)}: {ip}")
        
        # Get hostname for context
        hostname = resolve_hostname(ip)
        hostname_str = f" ({hostname})" if hostname else ""
        
        # Get MAC address and vendor
        mac = get_mac_address(ip)
        vendor = get_device_vendor(mac) if mac else None
        if mac:
            print(f"   🔗 MAC: {mac}")
            if vendor:
                print(f"   🏭 Vendor: {vendor}")
        
        # Show IP type
        local_ip = get_local_ip()
        public_ip = get_public_ip()
        if ip == local_ip:
            print(f"   🏠 Status: YOUR MACHINE")
        elif ip.startswith(('10.', '192.168.', '172.')):
            print(f"   🌐 Type: Private IP")
        elif ip == public_ip:
            print(f"   🌐 Type: Public IP")
        
        # Scan ports
        open_ports = scan_ports_for_ip(ip)
        
        if open_ports:
            print(f"   📋 Found {len(open_ports)} open ports:")
            scan_results[ip] = {
                'hostname': hostname,
                'open_ports': open_ports,
                'suspicious_ports': []
            }
            
            for port in open_ports:
                description = get_port_description(port)
                print(f"      🔸 Port {port}: {description}")
                
                # Check for suspicious ports
                suspicious_keywords = ['RAT', 'MALWARE', 'INSECURE', 'Back Orifice']
                if any(keyword in description for keyword in suspicious_keywords):
                    scan_results[ip]['suspicious_ports'].append(port)
                    print(f"         ⚠️  SUSPICIOUS PORT DETECTED!")
            
            # Check if device has suspicious ports
            if scan_results[ip]['suspicious_ports']:
                suspicious_devices.append(ip)
                print(f"   🚨 DEVICE {ip}{hostname_str} HAS SUSPICIOUS PORTS!")
        else:
            print(f"   ✅ No open ports found")
        
        print("-" * 50)
    
    # Display summary
    print("\n" + "="*60)
    print("📋 PORT SCAN SUMMARY")
    print("="*60)
    
    if suspicious_devices:
        print("🚨 SUSPICIOUS DEVICES FOUND:")
        for ip in suspicious_devices:
            hostname = scan_results[ip]['hostname']
            hostname_str = f" ({hostname})" if hostname else ""
            suspicious_ports = scan_results[ip]['suspicious_ports']
            print(f"   🔴 {ip}{hostname_str}")
            print(f"      Suspicious ports: {suspicious_ports}")
        print()
    else:
        print("✅ No suspicious devices found")
        print()
        
    print("📊 ALL DEVICES WITH OPEN PORTS:")
    for ip, data in scan_results.items():
        hostname = data['hostname']
        hostname_str = f" ({hostname})" if hostname else ""
        open_ports = data['open_ports']
        print(f"   📡 {ip}{hostname_str}: {open_ports}")
    
    # Save results option
    save_results = input("\n💾 Save port scan results to file? (y/N): ").strip().lower()
    if save_results in ['y', 'yes']:
        save_port_scan_results(scan_results, suspicious_devices)

def save_port_scan_results(scan_results, suspicious_devices):
    """Save port scan results to a file"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"port_scan_results_{timestamp}.txt"
    
    try:
        with open(filename, 'w') as f:
            f.write(f"Port Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n\n")
            
            if suspicious_devices:
                f.write("🚨 SUSPICIOUS DEVICES FOUND:\n")
                for ip in suspicious_devices:
                    hostname = scan_results[ip]['hostname']
                    hostname_str = f" ({hostname})" if hostname else ""
                    suspicious_ports = scan_results[ip]['suspicious_ports']
                    f.write(f"   🔴 {ip}{hostname_str}\n")
                    f.write(f"      Suspicious ports: {suspicious_ports}\n")
                f.write("\n")
            else:
                f.write("✅ No suspicious devices found\n\n")
            
            f.write("📊 ALL DEVICES WITH OPEN PORTS:\n")
            for ip, data in scan_results.items():
                hostname = data['hostname']
                hostname_str = f" ({hostname})" if hostname else ""
                open_ports = data['open_ports']
                port_descriptions = [f"{port} ({get_port_description(port)})" for port in open_ports]
                f.write(f"   📡 {ip}{hostname_str}:\n")
                for port_desc in port_descriptions:
                    f.write(f"      - {port_desc}\n")
                f.write("\n")
        
        print(f"✅ Port scan results saved to: {filename}")
    except Exception as e:
        print(f"❌ Error saving results: {e}")

def scan_single_ip_for_ports():
    """Scan a single IP address for open ports"""
    print("\n" + "="*60)
    print("🔍 SINGLE IP PORT SCANNER")
    print("="*60)
    
    ip = input("🔢 Enter IP address to scan: ").strip()
    
    if not ip:
        print("❌ No IP address provided")
        return
    
    # Validate IP format
    try:
        socket.inet_aton(ip)
    except socket.error:
        print("❌ Invalid IP address format")
        return
    
    # Check if IP is in ignore list
    ignored_ips = load_ignore_list()
    if ip in ignored_ips:
        print(f"🚫 IP {ip} is in the ignore list and will be skipped")
        remove_from_ignore = input("🔍 Remove from ignore list and scan anyway? (y/N): ").strip().lower()
        if remove_from_ignore in ['y', 'yes']:
            ignored_ips.remove(ip)
            save_ignore_list(ignored_ips)
            print(f"✅ Removed {ip} from ignore list")
        else:
            print("❌ Scan cancelled")
            return
    
    print(f"\n🔍 Scanning {ip} for open ports...")
    
    # First check if host is alive
    success, output = ping_host(ip)
    if not success:
        print(f"❌ Host {ip} is not responding to ping")
        continue_anyway = input("🔍 Continue with port scan anyway? (y/N): ").strip().lower()
        if continue_anyway not in ['y', 'yes']:
            return
    
    # Get hostname
    hostname = resolve_hostname(ip)
    hostname_str = f" ({hostname})" if hostname else ""
    print(f"📝 Hostname: {hostname if hostname else 'Unknown'}")
    
    # Get MAC address and vendor
    mac = get_mac_address(ip)
    vendor = get_device_vendor(mac) if mac else None
    if mac:
        print(f"🔗 MAC Address: {mac}")
        if vendor:
            print(f"🏭 Device Vendor: {vendor}")
    
    # Show IP type
    local_ip = get_local_ip()
    public_ip = get_public_ip()
    if ip == local_ip:
        print(f"🏠 Status: THIS IS YOUR MACHINE")
    elif ip.startswith(('10.', '192.168.', '172.')):
        print(f"🌐 IP Type: Private (Local Network)")
    elif ip == public_ip:
        print(f"🌐 IP Type: Public (Internet)")
    else:
        print(f"🌐 IP Type: Other")
    
    print()
    
    # Scan ports
    open_ports = scan_ports_for_ip(ip)
    
    if open_ports:
        print(f"\n📋 Found {len(open_ports)} open ports:")
        suspicious_ports = []
        
        for port in open_ports:
            description = get_port_description(port)
            print(f"   🔸 Port {port}: {description}")
            
            # Check for suspicious ports
            suspicious_keywords = ['RAT', 'MALWARE', 'INSECURE', 'Back Orifice']
            if any(keyword in description for keyword in suspicious_keywords):
                suspicious_ports.append(port)
                print(f"      ⚠️  SUSPICIOUS PORT DETECTED!")
        
        if suspicious_ports:
            print(f"\n🚨 SUSPICIOUS PORTS FOUND: {suspicious_ports}")
            print("💡 Consider blocking these ports if not needed")
    else:
        print(f"\n✅ No open ports found on {ip}")
    
    # Save results option
    save_results = input("\n💾 Save scan results to file? (y/N): ").strip().lower()
    if save_results in ['y', 'yes']:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"single_ip_scan_{ip.replace('.', '_')}_{timestamp}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write(f"Single IP Port Scan - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*60 + "\n\n")
                f.write(f"IP: {ip}\n")
                f.write(f"Hostname: {hostname if hostname else 'Unknown'}\n\n")
                
                if open_ports:
                    f.write("OPEN PORTS:\n")
                    for port in open_ports:
                        description = get_port_description(port)
                        f.write(f"   Port {port}: {description}\n")
                    
                    if suspicious_ports:
                        f.write(f"\nSUSPICIOUS PORTS: {suspicious_ports}\n")
                else:
                    f.write("No open ports found\n")
            
            print(f"✅ Scan results saved to: {filename}")
        except Exception as e:
            print(f"❌ Error saving results: {e}")

def get_ignore_list_filepath():
    """Get the filepath for the ignore list file"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, "IGNORED_IPs.txt")

def load_ignore_list():
    """Load the list of ignored IPs from file"""
    ignore_file = get_ignore_list_filepath()
    ignored_ips = []
    
    try:
        if os.path.exists(ignore_file):
            with open(ignore_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):  # Skip comments and empty lines
                        # Validate IP format
                        try:
                            socket.inet_aton(ip)
                            ignored_ips.append(ip)
                        except socket.error:
                            continue  # Skip invalid IPs
    except Exception as e:
        print(f"⚠️  Warning: Could not load ignore list: {e}")
    
    return ignored_ips

def save_ignore_list(ignored_ips):
    """Save the list of ignored IPs to file"""
    ignore_file = get_ignore_list_filepath()
    
    try:
        with open(ignore_file, 'w') as f:
            f.write("# IGNORED IPs - These IPs will be skipped during network scans\n")
            f.write("# Format: One IP address per line\n")
            f.write("# Last updated: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")
            f.write("#" + "="*50 + "\n\n")
            
            for ip in sorted(ignored_ips):
                f.write(f"{ip}\n")
        
        return True
    except Exception as e:
        print(f"❌ Error saving ignore list: {e}")
        return False

def manage_ignore_list():
    """Add or remove IPs from the ignore list"""
    print("\n" + "="*60)
    print("🚫 IGNORE LIST MANAGEMENT")
    print("="*60)
    
    # Load current ignore list
    ignored_ips = load_ignore_list()
    
    if ignored_ips:
        print("📋 Currently ignored IPs:")
        for ip in sorted(ignored_ips):
            print(f"   🚫 {ip}")
        print()
    else:
        print("📋 No IPs are currently ignored")
        print()
    
    while True:
        print("Options:")
        print("1. Add IP to ignore list")
        print("2. Remove IP from ignore list")
        print("3. View current ignore list")
        print("4. Clear all ignored IPs")
        print("5. Back to main menu")
        print()
        
        choice = input("🔢 Enter your choice (1-5): ").strip()
        
        if choice == "1":
            ip = input("🔢 Enter IP address to ignore: ").strip()
            if not ip:
                print("❌ No IP address provided")
                continue
            
            # Validate IP format
            try:
                socket.inet_aton(ip)
            except socket.error:
                print("❌ Invalid IP address format")
                continue
            
            if ip in ignored_ips:
                print(f"⚠️  IP {ip} is already in the ignore list")
            else:
                ignored_ips.append(ip)
                if save_ignore_list(ignored_ips):
                    print(f"✅ Added {ip} to ignore list")
                else:
                    print(f"❌ Failed to add {ip} to ignore list")
            
        elif choice == "2":
            if not ignored_ips:
                print("📋 No IPs to remove")
                continue
            
            print("📋 Currently ignored IPs:")
            for i, ip in enumerate(sorted(ignored_ips), 1):
                print(f"   {i}. {ip}")
            print()
            
            try:
                index = int(input("🔢 Enter number of IP to remove: ").strip()) - 1
                if 0 <= index < len(ignored_ips):
                    ip_to_remove = sorted(ignored_ips)[index]
                    ignored_ips.remove(ip_to_remove)
                    if save_ignore_list(ignored_ips):
                        print(f"✅ Removed {ip_to_remove} from ignore list")
                    else:
                        print(f"❌ Failed to remove {ip_to_remove} from ignore list")
                else:
                    print("❌ Invalid selection")
            except (ValueError, IndexError):
                print("❌ Invalid input")
                
        elif choice == "3":
            if ignored_ips:
                print("📋 Currently ignored IPs:")
                for ip in sorted(ignored_ips):
                    print(f"   🚫 {ip}")
            else:
                print("📋 No IPs are currently ignored")
            
        elif choice == "4":
            if not ignored_ips:
                print("📋 No IPs to clear")
                continue
            
            confirm = input("⚠️  Are you sure you want to clear all ignored IPs? (y/N): ").strip().lower()
            if confirm in ['y', 'yes']:
                ignored_ips.clear()
                if save_ignore_list(ignored_ips):
                    print("✅ Cleared all ignored IPs")
                else:
                    print("❌ Failed to clear ignored IPs")
        
        elif choice == "5":
            break
            
        else:
            print("⚠️  Invalid choice. Please enter 1-5.")
        
        print()

def filter_ignored_ips(ip_list):
    """Filter out ignored IPs from a list"""
    ignored_ips = load_ignore_list()
    if not ignored_ips:
        return ip_list
    
    filtered_ips = [ip for ip in ip_list if ip not in ignored_ips]
    
    if len(filtered_ips) != len(ip_list):
        ignored_count = len(ip_list) - len(filtered_ips)
        print(f"🚫 Skipped {ignored_count} ignored IP(s)")
    
    return filtered_ips

def show_main_menu():
    """Display the main menu"""
    print("1. Scan Network For All IPs")
    print("2. Scan Network For IPs With Known Host Names")
    print("3. Scan Network For All Open Ports")
    print("4. Scan Single IP For Open Ports")
    print("5. Compare Network's Current IPs With A Past List")
    print("6. Save Current IPs as a list")
    print("7. Manage Ignore List")
    print("8. Exit")
    print()

def main():
    color = set_random_color()
    print("                         d8b                     d8,                                       d8b ")
    print("                         ?88                    `8P                  d8P                   88P ")
    print("                          88b                                     d888888P                d88  ")
    print(" d888b8b   d8888b d8888b  888  d88' d8888b       88b?88,.d88b,      ?88'   d8888b  d8888b 888  ")
    print("d8P' ?88  d8b_,dPd8P' `P  888bd8P' d8P' ?88      88P`?88'  ?88      88P   d8P' ?88d8P' ?88?88  ")
    print("88b  ,88b 88b    88b     d88888b   88b  d88     d88   88b  d8P      88b   88b  d8888b  d88 88b ")
    print("`?88P'`88b`?888P'`?888P'd88' `?88b,`?8888P'    d88'   888888P'      `?8b  `?8888P'`?8888P'  88b")
    print("       )88                                            88P'                                     ")
    print("      ,88P                                           d88                                        ")
    print("  `?8888P                                            ?8P                                        ")
    print("="*120)
    print("🔍 Welcome to the Network Scanner!")
    print("💡 Choose an option from the menu below")
    print()
    
    # Check if running on Windows
    if platform.system() != "Windows":
        print("⚠️  This script is optimized for Windows")
        print("🐧 Some features may not work on other systems")
        print()
    
    # Store current IP list for comparison
    current_ips = []
    
    while True:
        show_main_menu()
        
        choice = input("🔢 Enter your choice (1-8): ").strip()
        
        if choice == "1":
            print("\n🔍 Option 1: Scan Network For All IPs")
            print("="*60)
            active_hosts = scan_network()
            if active_hosts:
                analyze_hosts(active_hosts)
                current_ips = active_hosts.copy()
                print(f"\n📊 Found {len(active_hosts)} active hosts")
            else:
                print("❌ No active hosts found")
            
        elif choice == "2":
            print("\n🔍 Option 2: Scan Network For IPs With Known Host Names")
            print("="*60)
            hosts_with_names = scan_network_with_hostnames()
            if hosts_with_names:
                current_ips = hosts_with_names.copy()
                print(f"\n📊 Found {len(hosts_with_names)} IPs with hostnames")
            else:
                print("❌ No IPs with hostnames found")
            
        elif choice == "3":
            print("\n🔍 Option 3: Scan Network For All Open Ports")
            print("="*60)
            if not current_ips:
                print("⚠️  No IP list available. Running full network scan first...")
                active_hosts = scan_network()
                if active_hosts:
                    current_ips = active_hosts.copy()
                else:
                    print("❌ No active hosts found")
                    continue
            
            scan_all_ips_for_ports(current_ips)
            
        elif choice == "4":
            print("\n🔍 Option 4: Scan Single IP For Open Ports")
            print("="*60)
            scan_single_ip_for_ports()
            
        elif choice == "5":
            print("\n🔍 Option 5: Compare Network's Current IPs With A Past List")
            print("="*60)
            if not current_ips:
                print("⚠️  No current IP list available. Running network scan first...")
                active_hosts = scan_network()
                if active_hosts:
                    current_ips = active_hosts.copy()
                else:
                    print("❌ No active hosts found")
                    continue
            
            filepath = input("📁 Enter path to previous IP list file: ").strip()
            if filepath:
                previous_ips = load_ips_from_file(filepath)
                if previous_ips:
                    # Filter both lists for ignored IPs for comparison
                    current_filtered = filter_ignored_ips(current_ips)
                    previous_filtered = filter_ignored_ips(previous_ips)
                    compare_ip_lists(current_filtered, previous_filtered)
                else:
                    print("❌ Could not load previous IP list")
            else:
                print("❌ No file path provided")
            
        elif choice == "6":
            print("\n🔍 Option 6: Save Current IPs as a list")
            print("="*60)
            print(f"DEBUG: current_ips has {len(current_ips) if current_ips else 0} items")
            print(f"DEBUG: current_ips content: {current_ips}")
            
            if not current_ips:
                print("⚠️  No current IP list available. Running network scan first...")
                active_hosts = scan_network()
                if active_hosts:
                    current_ips = active_hosts.copy()
                    print(f"DEBUG: After scan, current_ips has {len(current_ips)} items")
                else:
                    print("❌ No active hosts found")
                    continue
            
            # Filter out ignored IPs before saving
            current_filtered = filter_ignored_ips(current_ips)
            print(f"DEBUG: After filtering, current_filtered has {len(current_filtered) if current_filtered else 0} items")
            print(f"DEBUG: current_filtered content: {current_filtered}")
            
            if not current_filtered:
                print("❌ No IPs to save after filtering ignored IPs")
                continue
            
            print(f"📊 Ready to save {len(current_filtered)} IPs")
            filename = input("📁 Enter filename (or press Enter for auto-name): ").strip()
            if not filename:
                filename = None
            save_ips_to_file(current_filtered, filename)
            
        elif choice == "7":
            manage_ignore_list()
            
        elif choice == "8":
            print("\n👋 Goodbye!")
            reset_color()
            break
            
        else:
            print("⚠️  Invalid choice. Please enter 1-8.")
        
        # Wait for user to continue
        if choice in ["1", "2", "3", "4", "5", "6", "7"]:
            input("\n⏸️  Press Enter to continue...")
    
    print("\n" + "="*60)

if __name__ == "__main__":
    main() 