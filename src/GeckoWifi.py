import os
import sys
import subprocess
import platform
import socket
import requests
import re
import random
import time
from datetime import datetime

def set_random_color():
    """Set random terminal color"""
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

def print_banner():
    """Display the GeckoWifi banner"""
    print("                         d8b                                    d8,   ,d8888b  d8,                             d8b ")
    print("                         ?88                                   `8P    88P'    `8P        d8P                   88P ")
    print("                          88b                                      d888888P           d888888P                d88  ")
    print(" d888b8b   d8888b d8888b  888  d88' d8888b      ?88   d8P  d8P  88b  ?88'      88b      ?88'   d8888b  d8888b 888  ")
    print("d8P' ?88  d8b_,dPd8P' `P  888bd8P' d8P' ?88     d88  d8P' d8P'  88P  88P       88P      88P   d8P' ?88d8P' ?88?88  ")
    print("88b  ,88b 88b    88b     d88888b   88b  d88     ?8b ,88b ,88'  d88  d88       d88       88b   88b  d8888b  d88 88b ")
    print("`?88P'`88b`?888P'`?888P'd88' `?88b,`?8888P'     `?888P'888P'  d88' d88'      d88'       `?8b  `?8888P'`?8888P'  88b")
    print("       )88                                                                                                         ")
    print("      ,88P                                                                                                         ")
    print("  `?8888P                                                                                                          ")
    print("======📶 Welcome to Gecko WiFi Security Assessment Tool")
    print("💡 Choose an option from the menu below")
    print()

def run_command(command, shell=True):
    """Run a command and return success status, stdout, and stderr"""
    try:
        result = subprocess.run(command, shell=shell, capture_output=True, text=True, timeout=30)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)

def get_private_ip():
    """Get the local private IP address"""
    try:
        import socket
        # Create a socket to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None

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
                            import socket
                            socket.inet_aton(ip)
                            ignored_ips.append(ip)
                        except socket.error:
                            continue  # Skip invalid IPs
    except Exception as e:
        print(f"⚠️  Warning: Could not load ignore list: {e}")
    
    return ignored_ips

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

def get_wifi_info_windows():
    """Get WiFi information on Windows"""
    wifi_info = {}
    
    try:
        # Get current WiFi profile and interface name
        wifi_interface = None
        try:
            success, stdout, stderr = run_command('netsh wlan show interfaces')
            if success and stdout.strip():
                lines = stdout.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if 'Name' in line and ':' in line:
                        name_match = re.search(r'Name\s+:\s+(.+)', line)
                        if name_match:
                            wifi_interface = name_match.group(1).strip()
                    if 'SSID' in line and 'BSSID' not in line:
                        ssid_match = re.search(r'SSID\s+:\s+(.+)', line)
                        if ssid_match:
                            wifi_info['ssid'] = ssid_match.group(1).strip()
                    elif 'Signal' in line:
                        signal_match = re.search(r'Signal\s+:\s+(.+)', line)
                        if signal_match:
                            wifi_info['signal'] = signal_match.group(1).strip()
                    elif 'Radio type' in line:
                        radio_match = re.search(r'Radio type\s+:\s+(.+)', line)
                        if radio_match:
                            wifi_info['wifi_type'] = radio_match.group(1).strip()
                    elif 'Authentication' in line:
                        auth_match = re.search(r'Authentication\s+:\s+(.+)', line)
                        if auth_match:
                            wifi_info['authentication'] = auth_match.group(1).strip()
                    elif 'Cipher' in line:
                        cipher_match = re.search(r'Cipher\s+:\s+(.+)', line)
                        if cipher_match:
                            wifi_info['cipher'] = cipher_match.group(1).strip()
        except Exception as e:
            pass
        
        # Get connection type (WiFi vs Ethernet) - robust
        try:
            success, stdout, stderr = run_command('netsh interface show interface')
            if success and stdout.strip() and wifi_interface:
                lines = stdout.strip().split('\n')
                for line in lines:
                    if wifi_interface in line and 'Connected' in line:
                        wifi_info['connection_type'] = 'Wireless'
                        break
                else:
                    # If not found, check for any other connected interface
                    for line in lines:
                        if 'Ethernet' in line and 'Connected' in line:
                            wifi_info['connection_type'] = 'Ethernet'
                            break
            elif success and stdout.strip():
                # Fallback: if no wifi_interface, just check for any connected Wi-Fi
                for line in lines:
                    if 'Wi-Fi' in line and 'Connected' in line:
                        wifi_info['connection_type'] = 'Wireless'
                        break
                    elif 'Ethernet' in line and 'Connected' in line:
                        wifi_info['connection_type'] = 'Ethernet'
                        break
        except Exception as e:
            pass
        
        # Get internet type (public/private)
        try:
            # Try to get network profile
            success, stdout, stderr = run_command('netsh advfirewall show currentprofile')
            if success and stdout.strip():
                if 'Public' in stdout:
                    wifi_info['internet_type'] = 'Public'
                elif 'Private' in stdout:
                    wifi_info['internet_type'] = 'Private'
                else:
                    wifi_info['internet_type'] = 'Unknown'
        except:
            wifi_info['internet_type'] = 'Unknown'
        
        # Get IP information (IPv4 and IPv6)
        try:
            # Get IPv4
            s4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s4.connect(("8.8.8.8", 80))
            local_ipv4 = s4.getsockname()[0]
            s4.close()
            wifi_info['local_ipv4'] = local_ipv4
            wifi_info['ip_version'] = 'IPv4'
        except:
            wifi_info['local_ipv4'] = 'Unknown'
        
        try:
            # Get IPv6
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s6.connect(("2001:4860:4860::8888", 80))
            local_ipv6 = s6.getsockname()[0]
            s6.close()
            wifi_info['local_ipv6'] = local_ipv6
            if 'ip_version' not in wifi_info:
                wifi_info['ip_version'] = 'IPv6'
            else:
                wifi_info['ip_version'] = 'Dual Stack (IPv4 + IPv6)'
        except:
            wifi_info['local_ipv6'] = 'Not available'
        
        # Get public IP
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            public_ip = response.json()['ip']
            wifi_info['public_ip'] = public_ip
            # Determine if public IP is IPv4 or IPv6
            if ':' in public_ip:
                wifi_info['public_ip_version'] = 'IPv6'
            else:
                wifi_info['public_ip_version'] = 'IPv4'
        except:
            try:
                response = requests.get('https://httpbin.org/ip', timeout=5)
                public_ip = response.json()['origin']
                wifi_info['public_ip'] = public_ip
                # Determine if public IP is IPv4 or IPv6
                if ':' in public_ip:
                    wifi_info['public_ip_version'] = 'IPv6'
                else:
                    wifi_info['public_ip_version'] = 'IPv4'
            except:
                wifi_info['public_ip'] = 'Unknown'
                wifi_info['public_ip_version'] = 'Unknown'
        
    except Exception as e:
        print(f"Error getting WiFi info: {str(e)}")
    
    return wifi_info

def get_wifi_info_linux():
    """Get WiFi information on Linux"""
    wifi_info = {}
    
    try:
        # Get current WiFi interface
        success, stdout, stderr = run_command('iwgetid')
        if success and stdout.strip():
            ssid_match = re.search(r'ESSID:"([^"]+)"', stdout)
            if ssid_match:
                wifi_info['ssid'] = ssid_match.group(1)
        
        # Get WiFi interface details
        success, stdout, stderr = run_command('iwconfig')
        if success and stdout.strip():
            lines = stdout.strip().split('\n')
            for line in lines:
                if 'IEEE' in line:
                    ieee_match = re.search(r'IEEE\s+(\S+)', line)
                    if ieee_match:
                        wifi_info['wifi_type'] = ieee_match.group(1)
                elif 'Quality' in line:
                    quality_match = re.search(r'Quality=(\S+)', line)
                    if quality_match:
                        wifi_info['signal'] = quality_match.group(1)
        
        # Get connection type
        success, stdout, stderr = run_command('ip route get 8.8.8.8')
        if success and stdout.strip():
            if 'wlan' in stdout or 'wifi' in stdout:
                wifi_info['connection_type'] = 'Wireless'
            elif 'eth' in stdout or 'enp' in stdout:
                wifi_info['connection_type'] = 'Ethernet'
            else:
                wifi_info['connection_type'] = 'Unknown'
        
        # Get IP information (IPv4 and IPv6)
        try:
            # Get IPv4
            s4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s4.connect(("8.8.8.8", 80))
            local_ipv4 = s4.getsockname()[0]
            s4.close()
            wifi_info['local_ipv4'] = local_ipv4
            wifi_info['ip_version'] = 'IPv4'
        except:
            wifi_info['local_ipv4'] = 'Unknown'
        
        try:
            # Get IPv6
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s6.connect(("2001:4860:4860::8888", 80))
            local_ipv6 = s6.getsockname()[0]
            s6.close()
            wifi_info['local_ipv6'] = local_ipv6
            if 'ip_version' not in wifi_info:
                wifi_info['ip_version'] = 'IPv6'
            else:
                wifi_info['ip_version'] = 'Dual Stack (IPv4 + IPv6)'
        except:
            wifi_info['local_ipv6'] = 'Not available'
        
        # Get public IP
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            wifi_info['public_ip'] = response.json()['ip']
        except:
            try:
                response = requests.get('https://httpbin.org/ip', timeout=5)
                wifi_info['public_ip'] = response.json()['origin']
            except:
                wifi_info['public_ip'] = 'Unknown'
        
        # Set internet type based on network configuration
        wifi_info['internet_type'] = 'Unknown'  # Could be enhanced with network detection
        
    except Exception as e:
        print(f"Error getting WiFi info: {str(e)}")
    
    return wifi_info

def get_wifi_info_macos():
    """Get WiFi information on macOS"""
    wifi_info = {}
    
    try:
        # Get current WiFi SSID
        success, stdout, stderr = run_command('/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I')
        if success and stdout.strip():
            lines = stdout.strip().split('\n')
            for line in lines:
                if ' SSID: ' in line:
                    ssid_match = re.search(r'SSID:\s+(.+)', line)
                    if ssid_match:
                        wifi_info['ssid'] = ssid_match.group(1).strip()
                elif ' agrCtlRSSI: ' in line:
                    rssi_match = re.search(r'agrCtlRSSI:\s+(.+)', line)
                    if rssi_match:
                        wifi_info['signal'] = f"{rssi_match.group(1).strip()} dBm"
                elif ' lastTxRate: ' in line:
                    rate_match = re.search(r'lastTxRate:\s+(.+)', line)
                    if rate_match:
                        wifi_info['wifi_type'] = f"802.11 (Rate: {rate_match.group(1).strip()} Mbps)"
        
        # Get connection type
        success, stdout, stderr = run_command('networksetup -listallhardwareports')
        if success and stdout.strip():
            if 'Wi-Fi' in stdout and 'enabled' in stdout.lower():
                wifi_info['connection_type'] = 'Wireless'
            elif 'Ethernet' in stdout and 'enabled' in stdout.lower():
                wifi_info['connection_type'] = 'Ethernet'
            else:
                wifi_info['connection_type'] = 'Unknown'
        
        # Get IP information (IPv4 and IPv6)
        try:
            # Get IPv4
            s4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s4.connect(("8.8.8.8", 80))
            local_ipv4 = s4.getsockname()[0]
            s4.close()
            wifi_info['local_ipv4'] = local_ipv4
            wifi_info['ip_version'] = 'IPv4'
        except:
            wifi_info['local_ipv4'] = 'Unknown'
        
        try:
            # Get IPv6
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s6.connect(("2001:4860:4860::8888", 80))
            local_ipv6 = s6.getsockname()[0]
            s6.close()
            wifi_info['local_ipv6'] = local_ipv6
            if 'ip_version' not in wifi_info:
                wifi_info['ip_version'] = 'IPv6'
            else:
                wifi_info['ip_version'] = 'Dual Stack (IPv4 + IPv6)'
        except:
            wifi_info['local_ipv6'] = 'Not available'
        
        # Get public IP
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            public_ip = response.json()['ip']
            wifi_info['public_ip'] = public_ip
            # Determine if public IP is IPv4 or IPv6
            if ':' in public_ip:
                wifi_info['public_ip_version'] = 'IPv6'
            else:
                wifi_info['public_ip_version'] = 'IPv4'
        except:
            try:
                response = requests.get('https://httpbin.org/ip', timeout=5)
                public_ip = response.json()['origin']
                wifi_info['public_ip'] = public_ip
                # Determine if public IP is IPv4 or IPv6
                if ':' in public_ip:
                    wifi_info['public_ip_version'] = 'IPv6'
                else:
                    wifi_info['public_ip_version'] = 'IPv4'
            except:
                wifi_info['public_ip'] = 'Unknown'
                wifi_info['public_ip_version'] = 'Unknown'
        
        # Set internet type based on network configuration
        wifi_info['internet_type'] = 'Unknown'  # Could be enhanced with network detection
        
    except Exception as e:
        print(f"Error getting WiFi info: {str(e)}")
    
    return wifi_info

def check_current_wifi_info():
    """Check current WiFi information"""
    print("📶 Checking Current WiFi Information...")
    print()
    
    if platform.system() == "Windows":
        wifi_info = get_wifi_info_windows()
    elif platform.system() == "Linux":
        wifi_info = get_wifi_info_linux()
    elif platform.system() == "Darwin":  # macOS
        wifi_info = get_wifi_info_macos()
    else:
        print("❌ Unsupported operating system")
        return
    
    print("📊 Current WiFi Information:")
    print("="*60)
    
    # Display WiFi information
    if 'ssid' in wifi_info and wifi_info['ssid']:
        print(f"📡 SSID (Network Name):     {wifi_info['ssid']}")
    else:
        print(f"📡 SSID (Network Name):     Not connected")
    
    if 'connection_type' in wifi_info:
        print(f"🔌 Connection Type:         {wifi_info['connection_type']}")
    
    if 'wifi_type' in wifi_info:
        print(f"📶 WiFi Type:               {wifi_info['wifi_type']}")
    
    if 'signal' in wifi_info:
        print(f"📊 Signal Strength:         {wifi_info['signal']}")
    
    if 'authentication' in wifi_info:
        print(f"🔐 Authentication:          {wifi_info['authentication']}")
    
    if 'cipher' in wifi_info:
        print(f"🔒 Encryption:              {wifi_info['cipher']}")
    
    if 'local_ipv4' in wifi_info:
        print(f"🏠 Local IPv4 Address:      {wifi_info['local_ipv4']}")
    if 'local_ipv6' in wifi_info:
        print(f"🏠 Local IPv6 Address:      {wifi_info['local_ipv6']}")
    if 'ip_version' in wifi_info:
        print(f"🌐 Local IP Version:        {wifi_info['ip_version']}")
    if 'public_ip' in wifi_info:
        print(f"🌐 Public IP Address:       {wifi_info['public_ip']}")
    if 'public_ip_version' in wifi_info:
        print(f"🌍 Public IP Version:       {wifi_info['public_ip_version']}")
    
    if 'internet_type' in wifi_info:
        print(f"🌍 Internet Type:           {wifi_info['internet_type']}")
    
    print("="*60)
    
    # Security assessment
    print("\n🔒 Security Assessment:")
    print("-" * 30)
    
    if 'authentication' in wifi_info:
        if 'WPA2' in wifi_info['authentication'] or 'WPA3' in wifi_info['authentication']:
            print("✅ Strong encryption detected (WPA2/WPA3)")
        elif 'WPA' in wifi_info['authentication']:
            print("⚠️  Moderate encryption (WPA)")
        elif 'WEP' in wifi_info['authentication']:
            print("❌ Weak encryption (WEP) - Security risk!")
        else:
            print("❓ Unknown encryption type")
    
    if 'internet_type' in wifi_info and wifi_info['internet_type'] == 'Public':
        print("⚠️  Connected to public network - Use VPN for sensitive work")
    
    if 'connection_type' in wifi_info and wifi_info['connection_type'] == 'Wireless':
        print("📡 Wireless connection - Ensure network is secure")
    
    print()

def check_suspicious_dns_queries():
    """Check for suspicious DNS queries"""
    print("🔍 Checking for Suspicious DNS Queries...")
    print()
    
    suspicious_domains = [
        'malware.com', 'virus.com', 'trojan.com', 'backdoor.com',
        'keylogger.com', 'spy.com', 'crypto.com', 'miner.com',
        'bitcoin.com', 'ethereum.com', 'wallet.com', 'stealer.com',
        'injector.com', 'loader.com', 'dropper.com', 'payload.com',
        'command.com', 'control.com', 'remote.com', 'access.com',
        'vnc.com', 'rdp.com', 'ssh.com', 'telnet.com'
    ]
    
    suspicious_ips = [
        '8.8.8.8', '1.1.1.1', '208.67.222.222',  # Common DNS servers (usually safe)
        '192.168.1.1', '192.168.0.1', '10.0.0.1',  # Common router IPs
        '127.0.0.1', 'localhost'  # Localhost
    ]
    
    print("🔍 DNS Configuration Analysis:")
    print("="*60)
    
    # Check current DNS servers
    if platform.system() == "Windows":
        success, stdout, stderr = run_command('ipconfig /all')
        if success:
            lines = stdout.strip().split('\n')
            dns_servers = []
            for line in lines:
                if 'DNS Servers' in line and ':' in line:
                    dns_match = re.search(r'DNS Servers[^:]*:\s*(.+)', line)
                    if dns_match:
                        dns_servers.append(dns_match.group(1).strip())
            
            if dns_servers:
                print("📡 Current DNS Servers:")
                for i, dns in enumerate(dns_servers, 1):
                    print(f"   {i}. {dns}")
                
                # Check for suspicious DNS servers
                suspicious_found = []
                for dns in dns_servers:
                    for suspicious in suspicious_ips:
                        if suspicious in dns:
                            suspicious_found.append(dns)
                
                if suspicious_found:
                    print("\n⚠️  Potentially Suspicious DNS Servers:")
                    for dns in suspicious_found:
                        print(f"   • {dns} - Unusual DNS server")
                else:
                    print("\n✅ DNS servers appear normal")
            else:
                print("❌ Could not retrieve DNS server information")
    
    elif platform.system() == "Linux":
        success, stdout, stderr = run_command('cat /etc/resolv.conf')
        if success:
            lines = stdout.strip().split('\n')
            dns_servers = []
            for line in lines:
                if line.startswith('nameserver'):
                    dns = line.split()[1]
                    dns_servers.append(dns)
            
            if dns_servers:
                print("📡 Current DNS Servers:")
                for i, dns in enumerate(dns_servers, 1):
                    print(f"   {i}. {dns}")
                
                # Check for suspicious DNS servers
                suspicious_found = []
                for dns in dns_servers:
                    for suspicious in suspicious_ips:
                        if suspicious in dns:
                            suspicious_found.append(dns)
                
                if suspicious_found:
                    print("\n⚠️  Potentially Suspicious DNS Servers:")
                    for dns in suspicious_found:
                        print(f"   • {dns} - Unusual DNS server")
                else:
                    print("\n✅ DNS servers appear normal")
            else:
                print("❌ Could not retrieve DNS server information")
    
    elif platform.system() == "Darwin":  # macOS
        success, stdout, stderr = run_command('scutil --dns')
        if success:
            lines = stdout.strip().split('\n')
            dns_servers = []
            for line in lines:
                if 'nameserver' in line and '[' in line:
                    dns_match = re.search(r'nameserver\[(\d+)\]:\s*(.+)', line)
                    if dns_match:
                        dns_servers.append(dns_match.group(2).strip())
            
            if dns_servers:
                print("📡 Current DNS Servers:")
                for i, dns in enumerate(dns_servers, 1):
                    print(f"   {i}. {dns}")
                
                # Check for suspicious DNS servers
                suspicious_found = []
                for dns in dns_servers:
                    for suspicious in suspicious_ips:
                        if suspicious in dns:
                            suspicious_found.append(dns)
                
                if suspicious_found:
                    print("\n⚠️  Potentially Suspicious DNS Servers:")
                    for dns in suspicious_found:
                        print(f"   • {dns} - Unusual DNS server")
                else:
                    print("\n✅ DNS servers appear normal")
            else:
                print("❌ Could not retrieve DNS server information")
    
    # Check DNS cache for suspicious queries
    print("\n🔍 DNS Cache Analysis:")
    print("-" * 30)
    
    if platform.system() == "Windows":
        success, stdout, stderr = run_command('ipconfig /displaydns')
        if success:
            lines = stdout.strip().split('\n')
            suspicious_queries = []
            for line in lines:
                line_lower = line.lower()
                for domain in suspicious_domains:
                    if domain in line_lower:
                        suspicious_queries.append(line.strip())
            
            if suspicious_queries:
                print("⚠️  Suspicious DNS Queries Found:")
                for query in suspicious_queries[:10]:  # Show first 10
                    print(f"   • {query}")
                if len(suspicious_queries) > 10:
                    print(f"   ... and {len(suspicious_queries) - 10} more")
            else:
                print("✅ No suspicious DNS queries found in cache")
    
    elif platform.system() == "Linux":
        success, stdout, stderr = run_command('systemd-resolve --statistics')
        if success:
            print("📊 DNS Statistics available (check manually for suspicious queries)")
        else:
            print("ℹ️  DNS cache analysis not available on this system")
    
    elif platform.system() == "Darwin":  # macOS
        success, stdout, stderr = run_command('dscacheutil -cachedump -entries Host')
        if success:
            lines = stdout.strip().split('\n')
            suspicious_queries = []
            for line in lines:
                line_lower = line.lower()
                for domain in suspicious_domains:
                    if domain in line_lower:
                        suspicious_queries.append(line.strip())
            
            if suspicious_queries:
                print("⚠️  Suspicious DNS Queries Found:")
                for query in suspicious_queries[:10]:  # Show first 10
                    print(f"   • {query}")
                if len(suspicious_queries) > 10:
                    print(f"   ... and {len(suspicious_queries) - 10} more")
            else:
                print("✅ No suspicious DNS queries found in cache")
    
    print("\n🔒 Security Recommendations:")
    print("-" * 30)
    print("• Use trusted DNS servers (8.8.8.8, 1.1.1.1)")
    print("• Monitor DNS queries for unusual domains")
    print("• Consider using DNS over HTTPS (DoH)")
    print("• Check for DNS hijacking or poisoning")
    
    print("="*60)

def check_suspicious_routing_entries():
    """Check for suspicious routing entries"""
    print("🛣️  Checking for Suspicious Routing Entries...")
    print()
    
    print("🛣️  Routing Table Analysis:")
    print("="*60)
    
    if platform.system() == "Windows":
        success, stdout, stderr = run_command('route print')
        if success:
            lines = stdout.strip().split('\n')
            suspicious_routes = []
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('=') and not line.startswith('Network'):
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            destination = parts[0]
                            gateway = parts[2]
                            interface = parts[3] if len(parts) > 3 else 'Unknown'
                            
                            # Check for suspicious routes
                            suspicious_patterns = [
                                '0.0.0.0',  # Default route
                                '127.0.0.1',  # Loopback
                                '169.254.',  # Link-local
                                '224.0.0.',  # Multicast
                                '255.255.255.255'  # Broadcast
                            ]
                            
                            for pattern in suspicious_patterns:
                                if destination.startswith(pattern) and gateway != '0.0.0.0':
                                    suspicious_routes.append({
                                        'destination': destination,
                                        'gateway': gateway,
                                        'interface': interface,
                                        'reason': f'Suspicious route to {pattern}'
                                    })
                                    break
                        except (ValueError, IndexError):
                            continue
            
            if suspicious_routes:
                print("⚠️  Suspicious Routing Entries Found:")
                for route in suspicious_routes:
                    print(f"   • {route['destination']} -> {route['gateway']}")
                    print(f"     Interface: {route['interface']}")
                    print(f"     Reason: {route['reason']}")
                    print()
            else:
                print("✅ No suspicious routing entries found")
    
    elif platform.system() == "Linux":
        success, stdout, stderr = run_command('route -n')
        if success:
            lines = stdout.strip().split('\n')
            suspicious_routes = []
            
            for line in lines:
                if line and not line.startswith('Kernel'):
                    parts = line.split()
                    if len(parts) >= 8:
                        try:
                            destination = parts[0]
                            gateway = parts[1]
                            interface = parts[7]
                            
                            # Check for suspicious routes
                            suspicious_patterns = [
                                '0.0.0.0',  # Default route
                                '127.0.0.1',  # Loopback
                                '169.254.',  # Link-local
                                '224.0.0.',  # Multicast
                                '255.255.255.255'  # Broadcast
                            ]
                            
                            for pattern in suspicious_patterns:
                                if destination.startswith(pattern) and gateway != '0.0.0.0':
                                    suspicious_routes.append({
                                        'destination': destination,
                                        'gateway': gateway,
                                        'interface': interface,
                                        'reason': f'Suspicious route to {pattern}'
                                    })
                                    break
                        except (ValueError, IndexError):
                            continue
            
            if suspicious_routes:
                print("⚠️  Suspicious Routing Entries Found:")
                for route in suspicious_routes:
                    print(f"   • {route['destination']} -> {route['gateway']}")
                    print(f"     Interface: {route['interface']}")
                    print(f"     Reason: {route['reason']}")
                    print()
            else:
                print("✅ No suspicious routing entries found")
    
    elif platform.system() == "Darwin":  # macOS
        success, stdout, stderr = run_command('netstat -rn')
        if success:
            lines = stdout.strip().split('\n')
            suspicious_routes = []
            
            for line in lines:
                if line and not line.startswith('Routing'):
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            destination = parts[0]
                            gateway = parts[1]
                            interface = parts[3]
                            
                            # Check for suspicious routes
                            suspicious_patterns = [
                                'default',  # Default route
                                '127.0.0.1',  # Loopback
                                '169.254.',  # Link-local
                                '224.0.0.',  # Multicast
                                '255.255.255.255'  # Broadcast
                            ]
                            
                            for pattern in suspicious_patterns:
                                if destination.startswith(pattern) and gateway != '0.0.0.0':
                                    suspicious_routes.append({
                                        'destination': destination,
                                        'gateway': gateway,
                                        'interface': interface,
                                        'reason': f'Suspicious route to {pattern}'
                                    })
                                    break
                        except (ValueError, IndexError):
                            continue
            
            if suspicious_routes:
                print("⚠️  Suspicious Routing Entries Found:")
                for route in suspicious_routes:
                    print(f"   • {route['destination']} -> {route['gateway']}")
                    print(f"     Interface: {route['interface']}")
                    print(f"     Reason: {route['reason']}")
                    print()
            else:
                print("✅ No suspicious routing entries found")
    
    print("\n🔒 Security Recommendations:")
    print("-" * 30)
    print("• Monitor routing table for unauthorized changes")
    print("• Check for route hijacking or manipulation")
    print("• Verify default gateway is correct")
    print("• Look for routes to suspicious destinations")
    
    print("="*60)

def check_unauthorized_network_adapters():
    """Check for unauthorized network adapters"""
    print("🔌 Checking for Unauthorized Network Adapters...")
    print()
    
    print("🔌 Network Adapter Analysis:")
    print("="*60)
    
    if platform.system() == "Windows":
        success, stdout, stderr = run_command('netsh interface show interface')
        if success:
            lines = stdout.strip().split('\n')
            adapters = []
            
            for line in lines:
                if line and not line.startswith('Admin') and not line.startswith('='):
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            admin_state = parts[0]
                            state = parts[1]
                            interface_type = parts[2]
                            interface_name = ' '.join(parts[3:])
                            
                            adapters.append({
                                'admin_state': admin_state,
                                'state': state,
                                'type': interface_type,
                                'name': interface_name
                            })
                        except (ValueError, IndexError):
                            continue
            
            if adapters:
                print("📡 Network Adapters Found:")
                for i, adapter in enumerate(adapters, 1):
                    status_icon = "✅" if adapter['state'] == 'Connected' else "❌"
                    print(f"   {i}. {status_icon} {adapter['name']}")
                    print(f"      Type: {adapter['type']} | State: {adapter['state']}")
                    print()
                
                # Check for suspicious adapters
                suspicious_adapters = []
                for adapter in adapters:
                    name_lower = adapter['name'].lower()
                    suspicious_keywords = [
                        'virtual', 'vpn', 'tunnel', 'bridge', 'tap',
                        'loopback', 'pseudo', 'fake', 'dummy'
                    ]
                    
                    for keyword in suspicious_keywords:
                        if keyword in name_lower:
                            suspicious_adapters.append({
                                'adapter': adapter,
                                'keyword': keyword
                            })
                            break
                
                if suspicious_adapters:
                    print("⚠️  Potentially Suspicious Network Adapters:")
                    for item in suspicious_adapters:
                        adapter = item['adapter']
                        keyword = item['keyword']
                        print(f"   • {adapter['name']}")
                        print(f"     Type: {adapter['type']} | State: {adapter['state']}")
                        print(f"     Reason: Contains '{keyword}' in name")
                        print()
                else:
                    print("✅ No suspicious network adapters detected")
            else:
                print("❌ Could not retrieve network adapter information")
    
    elif platform.system() == "Linux":
        success, stdout, stderr = run_command('ip link show')
        if success:
            lines = stdout.strip().split('\n')
            adapters = []
            
            for line in lines:
                if ':' in line and not line.startswith(' '):
                    try:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            adapter_name = parts[1].strip()
                            if adapter_name and not adapter_name.startswith('lo'):  # Skip loopback
                                adapters.append(adapter_name)
                    except (ValueError, IndexError):
                        continue
            
            if adapters:
                print("📡 Network Adapters Found:")
                for i, adapter in enumerate(adapters, 1):
                    print(f"   {i}. {adapter}")
                
                # Check for suspicious adapters
                suspicious_adapters = []
                for adapter in adapters:
                    adapter_lower = adapter.lower()
                    suspicious_keywords = [
                        'veth', 'docker', 'br-', 'virbr', 'vmnet',
                        'tun', 'tap', 'vpn', 'bridge', 'pseudo'
                    ]
                    
                    for keyword in suspicious_keywords:
                        if keyword in adapter_lower:
                            suspicious_adapters.append({
                                'adapter': adapter,
                                'keyword': keyword
                            })
                            break
                
                if suspicious_adapters:
                    print("\n⚠️  Potentially Suspicious Network Adapters:")
                    for item in suspicious_adapters:
                        adapter = item['adapter']
                        keyword = item['keyword']
                        print(f"   • {adapter}")
                        print(f"     Reason: Contains '{keyword}' in name")
                        print()
                else:
                    print("\n✅ No suspicious network adapters detected")
            else:
                print("❌ Could not retrieve network adapter information")
    
    elif platform.system() == "Darwin":  # macOS
        success, stdout, stderr = run_command('networksetup -listallhardwareports')
        if success:
            lines = stdout.strip().split('\n')
            adapters = []
            current_adapter = {}
            
            for line in lines:
                line = line.strip()
                if line.startswith('Hardware Port:'):
                    if current_adapter:
                        adapters.append(current_adapter)
                    current_adapter = {'port': line.split(':', 1)[1].strip()}
                elif line.startswith('Device:'):
                    current_adapter['device'] = line.split(':', 1)[1].strip()
                elif line.startswith('Ethernet Address:'):
                    current_adapter['mac'] = line.split(':', 1)[1].strip()
            
            if current_adapter:
                adapters.append(current_adapter)
            
            if adapters:
                print("📡 Network Adapters Found:")
                for i, adapter in enumerate(adapters, 1):
                    print(f"   {i}. {adapter.get('port', 'Unknown')}")
                    if 'device' in adapter:
                        print(f"      Device: {adapter['device']}")
                    if 'mac' in adapter:
                        print(f"      MAC: {adapter['mac']}")
                    print()
                
                # Check for suspicious adapters
                suspicious_adapters = []
                for adapter in adapters:
                    port_lower = adapter.get('port', '').lower()
                    device_lower = adapter.get('device', '').lower()
                    
                    suspicious_keywords = [
                        'virtual', 'vpn', 'tunnel', 'bridge', 'tap',
                        'pseudo', 'fake', 'dummy', 'vmnet'
                    ]
                    
                    for keyword in suspicious_keywords:
                        if keyword in port_lower or keyword in device_lower:
                            suspicious_adapters.append({
                                'adapter': adapter,
                                'keyword': keyword
                            })
                            break
                
                if suspicious_adapters:
                    print("⚠️  Potentially Suspicious Network Adapters:")
                    for item in suspicious_adapters:
                        adapter = item['adapter']
                        keyword = item['keyword']
                        print(f"   • {adapter.get('port', 'Unknown')}")
                        print(f"     Device: {adapter.get('device', 'Unknown')}")
                        print(f"     Reason: Contains '{keyword}' in name")
                        print()
                else:
                    print("✅ No suspicious network adapters detected")
            else:
                print("❌ Could not retrieve network adapter information")
    
    print("\n🔒 Security Recommendations:")
    print("-" * 30)
    print("• Monitor for unauthorized network adapters")
    print("• Check for virtual adapters or VPN tunnels")
    print("• Verify all adapters are legitimate")
    print("• Look for hidden or disguised adapters")
    
    print("="*60)

def scan_ftp_servers():
    """Scan the network for FTP servers using efficient methods"""
    print("📁 Scanning Network for FTP Servers...")
    print()
    
    # Get local network information
    local_ip = get_private_ip()
    if not local_ip:
        print("❌ Could not determine local IP address")
        return
    
    # Extract network prefix (e.g., 192.168.1.0/24)
    ip_parts = local_ip.split('.')
    if len(ip_parts) != 4:
        print("❌ Invalid local IP address format")
        return
    
    network_prefix = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
    print(f"🔍 Scanning network: {network_prefix}.0/24")
    print()
    
    # Use efficient network scanning methods
    print("🔍 Step 1: Discovering active hosts...")
    active_hosts = []
    
    if platform.system() == "Windows":
        # Windows: Use arp-scan or efficient ping sweep
        print("   Using efficient network discovery...")
        
        # Try arp-scan first (if available)
        success, stdout, stderr = run_command('arp -a')
        if success and stdout.strip():
            lines = stdout.strip().split('\n')
            for line in lines:
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    if ip.startswith(network_prefix) and ip != local_ip and ip not in active_hosts:
                        active_hosts.append(ip)
                        print(f"   ✅ Active host found: {ip}")
        
        # If no hosts found via arp, try a quick ping sweep of common ranges
        if not active_hosts:
            print("   Using quick ping sweep of common ranges...")
            # Common ranges: 1-10, 100-110, 200-210
            ranges = [(1, 10), (100, 110), (200, 210)]
            for start, end in ranges:
                for i in range(start, end + 1):
                    ip = f"{network_prefix}.{i}"
                    if ip == local_ip:
                        continue
                    
                    # Quick ping with timeout
                    cmd = f'ping -n 1 -w 1000 {ip}'
                    success, stdout, stderr = run_command(cmd)
                    
                    if success and "TTL=" in stdout:
                        active_hosts.append(ip)
                        print(f"   ✅ Active host found: {ip}")
    
    elif platform.system() in ["Linux", "Darwin"]:
        # Linux/macOS: Use arp-scan or nmap
        print("   Using efficient network discovery...")
        
        # Try arp-scan first (most efficient)
        success, stdout, stderr = run_command('arp-scan --localnet --timeout 1000')
        if success and stdout.strip():
            lines = stdout.strip().split('\n')
            for line in lines:
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    if ip.startswith(network_prefix) and ip != local_ip and ip not in active_hosts:
                        active_hosts.append(ip)
                        print(f"   ✅ Active host found: {ip}")
        
        # Fallback to nmap if arp-scan not available
        if not active_hosts:
            print("   Using nmap quick scan...")
            nmap_cmd = f"nmap -sn {network_prefix}.0/24 --max-retries 1 --host-timeout 2s"
            success, stdout, stderr = run_command(nmap_cmd)
            
            if success and stdout:
                lines = stdout.strip().split('\n')
                for line in lines:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        if ip != local_ip and ip not in active_hosts:
                            active_hosts.append(ip)
                            print(f"   ✅ Active host found: {ip}")
        
        # Last resort: quick ping sweep
        if not active_hosts:
            print("   Using quick ping sweep...")
            for i in range(1, 255):
                ip = f"{network_prefix}.{i}"
                if ip == local_ip:
                    continue
                
                ping_cmd = f"ping -c 1 -W 1 {ip}"
                success, stdout, stderr = run_command(ping_cmd)
                
                if success and "1 received" in stdout:
                    active_hosts.append(ip)
                    print(f"   ✅ Active host found: {ip}")
    
    print(f"\n📊 Found {len(active_hosts)} active hosts on the network")
    
    # Filter out ignored IPs
    active_hosts = filter_ignored_ips(active_hosts)
    
    if not active_hosts:
        print("❌ No active hosts found after filtering ignored IPs.")
        return
    
    # Step 2: Scan FTP ports efficiently
    print(f"\n🔍 Step 2: Scanning FTP ports on {len(active_hosts)} active hosts...")
    ftp_servers = []
    ftp_ports = [21, 2121, 990, 989, 1337, 8080, 8000, 8888, 9999]  # Standard FTP, alternative FTP, FTPS, custom ports
    
    for host in active_hosts:
        print(f"🔍 Checking {host} for FTP services...")
        
        for port in ftp_ports:
            try:
                if platform.system() == "Windows":
                    # Windows: Try multiple methods for port detection
                    
                    # Method 1: Test-NetConnection
                    cmd = f'powershell -Command "Test-NetConnection -ComputerName {host} -Port {port} -InformationLevel Quiet -WarningAction SilentlyContinue"'
                    success, stdout, stderr = run_command(cmd, timeout=5)
                    
                    # Method 2: If Test-NetConnection fails, try telnet-style connection
                    if not success or "True" not in stdout:
                        cmd = f'powershell -Command "try {{ $tcp = New-Object System.Net.Sockets.TcpClient; $tcp.Connect(\'{host}\', {port}); $tcp.Close(); Write-Output \'True\' }} catch {{ Write-Output \'False\' }}"'
                        success, stdout, stderr = run_command(cmd, timeout=3)
                    
                    if success and "True" in stdout:
                        # Try to get FTP banner
                        banner_cmd = f'powershell -Command "try {{ $tcp = New-Object System.Net.Sockets.TcpClient; $tcp.Connect(\'{host}\', {port}); $stream = $tcp.GetStream(); $stream.ReadTimeout = 3000; $reader = New-Object System.IO.StreamReader($stream); $banner = $reader.ReadLine(); $tcp.Close(); Write-Output $banner }} catch {{ Write-Output \'No banner\' }}"'
                        banner_success, banner_output, _ = run_command(banner_cmd, timeout=5)
                        
                        banner = banner_output.strip() if banner_success and banner_output.strip() else "Unknown FTP Server"
                        
                        ftp_servers.append({
                            'ip': host,
                            'port': port,
                            'banner': banner,
                            'connection_string': f"ftp://{host}:{port}"
                        })
                        print(f"   ✅ Found FTP server at {host}:{port}")
                
                elif platform.system() in ["Linux", "Darwin"]:
                    # Linux/macOS: Try multiple methods
                    
                    # Method 1: netcat
                    nc_cmd = f"timeout 3 bash -c 'echo \"\" | nc {host} {port}'"
                    success, stdout, stderr = run_command(nc_cmd)
                    
                    # Method 2: If netcat fails, try telnet
                    if not success or not stdout.strip():
                        telnet_cmd = f"timeout 3 bash -c 'echo \"\" | telnet {host} {port}'"
                        success, stdout, stderr = run_command(telnet_cmd)
                    
                    # Method 3: If both fail, try direct socket connection
                    if not success or not stdout.strip():
                        python_cmd = f"python3 -c \"import socket; s=socket.socket(); s.settimeout(3); result=s.connect_ex(('{host}', {port})); s.close(); exit(0 if result==0 else 1)\""
                        success, stdout, stderr = run_command(python_cmd)
                        
                        if success:
                            # If socket connection works, try to get banner
                            banner_cmd = f"timeout 3 bash -c 'echo \"\" | nc {host} {port}'"
                            banner_success, banner_output, _ = run_command(banner_cmd)
                            stdout = banner_output
                    
                    if success and stdout.strip():
                        banner = stdout.strip() if stdout.strip() else "Unknown FTP Server"
                        
                        ftp_servers.append({
                            'ip': host,
                            'port': port,
                            'banner': banner,
                            'connection_string': f"ftp://{host}:{port}"
                        })
                        print(f"   ✅ Found FTP server at {host}:{port}")
                
            except Exception as e:
                continue  # Skip errors silently for speed
    
    print("\n📁 FTP Servers Found:")
    print("="*80)
    
    if not ftp_servers:
        print("✅ No FTP servers found on the network")
    else:
        print(f"📊 Found {len(ftp_servers)} FTP server(s):")
        print()
        
        for i, server in enumerate(ftp_servers, 1):
            print(f"{i:2}. 📁 FTP Server at {server['ip']}:{server['port']}")
            print(f"    Banner: {server['banner']}")
            print(f"    Connection: {server['connection_string']}")
            
            # Provide connection examples
            print(f"    📝 Connection Examples:")
            print(f"       • Browser: {server['connection_string']}")
            print(f"       • Command line: ftp {server['ip']} {server['port']}")
            print(f"       • FileZilla: {server['ip']}:{server['port']}")
            
            # Security warning for non-standard ports
            if server['port'] != 21:
                print(f"       ⚠️  Non-standard port detected!")
            
            print()
    
    print("🔒 Security Recommendations:")
    print("-" * 40)
    print("• Verify all FTP servers are legitimate")
    print("• Check for anonymous access")
    print("• Use SFTP/FTPS for secure file transfers")
    print("• Monitor for unauthorized FTP servers")
    print("• Consider blocking FTP if not needed")
    
    print("="*80)

def scan_nearby_wifis():
    """Scan for nearby WiFi networks and show their security status"""
    print("\n" + "="*80)
    print("📡 SCANNING NEARBY WIFI NETWORKS")
    print("="*80)
    print("🔍 This will help detect potential ARP spoofing attempts with cloned networks")
    print()
    
    system = platform.system()
    
    if system == "Windows":
        scan_nearby_wifis_windows()
    elif system == "Linux":
        scan_nearby_wifis_linux()
    elif system == "Darwin":  # macOS
        scan_nearby_wifis_macos()
    else:
        print("❌ Unsupported operating system for WiFi scanning")
        return

def scan_nearby_wifis_windows():
    """Scan nearby WiFi networks on Windows"""
    print("🔄 Scanning for nearby WiFi networks...")
    print()
    
    try:
        # Use netsh to scan for available networks
        success, stdout, stderr = run_command('netsh wlan show networks mode=bssid')
        
        if not success:
            print("❌ Failed to scan WiFi networks")
            print(f"Error: {stderr}")
            return
        
        networks = []
        current_network = {}
        
        lines = stdout.strip().split('\n')
        for line in lines:
            line = line.strip()
            
            if 'SSID' in line and 'BSSID' not in line and ':' in line:
                # New network found
                if current_network:
                    networks.append(current_network)
                
                ssid_match = re.search(r'SSID\s+\d+\s+:\s+(.+)', line)
                if ssid_match:
                    current_network = {'ssid': ssid_match.group(1).strip()}
                else:
                    current_network = {'ssid': 'Unknown'}
            
            elif 'Network type' in line and ':' in line:
                type_match = re.search(r'Network type\s+:\s+(.+)', line)
                if type_match and current_network:
                    current_network['type'] = type_match.group(1).strip()
            
            elif 'Authentication' in line and ':' in line:
                auth_match = re.search(r'Authentication\s+:\s+(.+)', line)
                if auth_match and current_network:
                    current_network['authentication'] = auth_match.group(1).strip()
            
            elif 'Encryption' in line and ':' in line:
                enc_match = re.search(r'Encryption\s+:\s+(.+)', line)
                if enc_match and current_network:
                    current_network['encryption'] = enc_match.group(1).strip()
            
            elif 'Signal' in line and ':' in line:
                signal_match = re.search(r'Signal\s+:\s+(.+)', line)
                if signal_match and current_network:
                    current_network['signal'] = signal_match.group(1).strip()
        
        # Add the last network
        if current_network:
            networks.append(current_network)
        
        if not networks:
            print("❌ No WiFi networks found")
            return
        
        # Remove duplicates based on SSID
        unique_networks = []
        seen_ssids = set()
        for network in networks:
            if network.get('ssid') and network['ssid'] not in seen_ssids:
                unique_networks.append(network)
                seen_ssids.add(network['ssid'])
        
        print(f"📡 Found {len(networks)} nearby WiFi networks:")
        print()
        
        # Sort by security level (open networks first, then by signal strength)
        def security_score(network):
            auth = network.get('authentication', '').lower()
            if 'open' in auth or 'none' in auth:
                return 0  # Open networks (most suspicious)
            elif 'wpa' in auth or 'wep' in auth:
                return 1  # Protected networks
            else:
                return 2  # Unknown/other
        
        unique_networks.sort(key=lambda x: (security_score(x), x.get('ssid', '')))
        
        for i, network in enumerate(unique_networks, 1):
            ssid = network.get('ssid', 'Unknown')
            auth = network.get('authentication', 'Unknown')
            encryption = network.get('encryption', 'Unknown')
            signal = network.get('signal', 'Unknown')
            
            # Determine security status
            if 'open' in auth.lower() or 'none' in auth.lower():
                security_icon = "🔓"
                security_status = "OPEN (Unsecured)"
                risk_level = "HIGH"
            elif 'wpa' in auth.lower():
                security_icon = "🔒"
                security_status = "PROTECTED (WPA/WPA2/WPA3)"
                risk_level = "LOW"
            elif 'wep' in auth.lower():
                security_icon = "⚠️"
                security_status = "WEAK (WEP)"
                risk_level = "MEDIUM"
            else:
                security_icon = "❓"
                security_status = "UNKNOWN"
                risk_level = "UNKNOWN"
            
            print(f"{i:2d}. {security_icon} {ssid}")
            print(f"    🔐 Security: {security_status}")
            print(f"    📡 Signal: {signal}")
            print(f"    🎯 Risk Level: {risk_level}")
            print()
        
        # Security analysis
        open_networks = [n for n in unique_networks if 'open' in n.get('authentication', '').lower() or 'none' in n.get('authentication', '').lower()]
        
        print("🔒 Security Analysis:")
        print("-" * 40)
        print(f"• Total networks found: {len(unique_networks)}")
        print(f"• Open networks: {len(open_networks)}")
        print(f"• Protected networks: {len(unique_networks) - len(open_networks)}")
        print()
        
        if open_networks:
            print("⚠️  WARNING: Open networks detected!")
            print("   These could be:")
            print("   • Legitimate public WiFi")
            print("   • Evil twin attacks (cloned networks)")
            print("   • Rogue access points")
            print("   • ARP spoofing attempts")
            print()
            print("🔍 Recommendations:")
            print("• Avoid connecting to open networks")
            print("• Verify network names with legitimate sources")
            print("• Use VPN when connecting to public WiFi")
            print("• Monitor for duplicate network names")
        
        print("="*80)
        
    except Exception as e:
        print(f"❌ Error scanning WiFi networks: {e}")

def scan_nearby_wifis_linux():
    """Scan nearby WiFi networks on Linux"""
    print("🔄 Scanning for nearby WiFi networks...")
    print()
    
    try:
        # Try using iwlist first (more detailed)
        success, stdout, stderr = run_command('iwlist scan 2>/dev/null | grep -E "(ESSID|Encryption key|Signal level)"')
        
        if not success or not stdout.strip():
            # Fallback to nmcli
            success, stdout, stderr = run_command('nmcli -t -f SSID,SECURITY,SIGNAL device wifi list')
            
            if not success:
                print("❌ Failed to scan WiFi networks")
                print("   Make sure you have iwlist or nmcli available")
                return
        
        networks = []
        
        if 'ESSID' in stdout:
            # iwlist output
            lines = stdout.strip().split('\n')
            current_network = {}
            
            for line in lines:
                line = line.strip()
                
                if 'ESSID' in line:
                    if current_network:
                        networks.append(current_network)
                    
                    essid_match = re.search(r'ESSID:"([^"]*)"', line)
                    if essid_match:
                        current_network = {'ssid': essid_match.group(1)}
                    else:
                        current_network = {'ssid': 'Unknown'}
                
                elif 'Encryption key' in line:
                    if current_network:
                        if 'off' in line.lower():
                            current_network['authentication'] = 'Open'
                        else:
                            current_network['authentication'] = 'Protected'
                
                elif 'Signal level' in line:
                    if current_network:
                        signal_match = re.search(r'Signal level=([^\\s]+)', line)
                        if signal_match:
                            current_network['signal'] = signal_match.group(1)
            
            if current_network:
                networks.append(current_network)
        
        else:
            # nmcli output
            lines = stdout.strip().split('\n')
            for line in lines:
                if line.strip():
                    parts = line.split(':')
                    if len(parts) >= 3:
                        ssid = parts[0] if parts[0] != '--' else 'Hidden'
                        security = parts[1] if parts[1] != '--' else 'Unknown'
                        signal = parts[2] if len(parts) > 2 else 'Unknown'
                        
                        networks.append({
                            'ssid': ssid,
                            'authentication': security,
                            'signal': signal
                        })
        
        if not networks:
            print("❌ No WiFi networks found")
            return
        
        # Remove duplicates and display
        unique_networks = []
        seen_ssids = set()
        for network in networks:
            if network.get('ssid') and network['ssid'] not in seen_ssids:
                unique_networks.append(network)
                seen_ssids.add(network['ssid'])
        
        print(f"📡 Found {len(unique_networks)} nearby WiFi networks:")
        print()
        
        for i, network in enumerate(unique_networks, 1):
            ssid = network.get('ssid', 'Unknown')
            auth = network.get('authentication', 'Unknown')
            signal = network.get('signal', 'Unknown')
            
            # Determine security status
            if 'open' in auth.lower() or 'none' in auth.lower() or auth == '--':
                security_icon = "🔓"
                security_status = "OPEN (Unsecured)"
                risk_level = "HIGH"
            elif 'wpa' in auth.lower() or 'wep' in auth.lower():
                security_icon = "🔒"
                security_status = "PROTECTED"
                risk_level = "LOW"
            else:
                security_icon = "❓"
                security_status = "UNKNOWN"
                risk_level = "UNKNOWN"
            
            print(f"{i:2d}. {security_icon} {ssid}")
            print(f"    🔐 Security: {security_status}")
            print(f"    📡 Signal: {signal}")
            print(f"    🎯 Risk Level: {risk_level}")
            print()
        
        # Security analysis
        open_networks = [n for n in unique_networks if 'open' in n.get('authentication', '').lower() or n.get('authentication') == '--']
        
        print("🔒 Security Analysis:")
        print("-" * 40)
        print(f"• Total networks found: {len(unique_networks)}")
        print(f"• Open networks: {len(open_networks)}")
        print(f"• Protected networks: {len(unique_networks) - len(open_networks)}")
        print()
        
        if open_networks:
            print("⚠️  WARNING: Open networks detected!")
            print("   These could be:")
            print("   • Legitimate public WiFi")
            print("   • Evil twin attacks (cloned networks)")
            print("   • Rogue access points")
            print("   • ARP spoofing attempts")
            print()
            print("🔍 Recommendations:")
            print("• Avoid connecting to open networks")
            print("• Verify network names with legitimate sources")
            print("• Use VPN when connecting to public WiFi")
            print("• Monitor for duplicate network names")
        
        print("="*80)
        
    except Exception as e:
        print(f"❌ Error scanning WiFi networks: {e}")

def scan_nearby_wifis_macos():
    """Scan nearby WiFi networks on macOS"""
    print("🔄 Scanning for nearby WiFi networks...")
    print()
    
    try:
        # Use airport command to scan
        success, stdout, stderr = run_command('/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s')
        
        if not success:
            print("❌ Failed to scan WiFi networks")
            print(f"Error: {stderr}")
            return
        
        networks = []
        lines = stdout.strip().split('\n')
        
        # Skip header line
        for line in lines[1:]:
            if line.strip():
                parts = line.split()
                if len(parts) >= 4:
                    ssid = parts[0]
                    security = parts[6] if len(parts) > 6 else 'Unknown'
                    signal = parts[1] if len(parts) > 1 else 'Unknown'
                    
                    networks.append({
                        'ssid': ssid,
                        'authentication': security,
                        'signal': signal
                    })
        
        if not networks:
            print("❌ No WiFi networks found")
            return
        
        print(f"📡 Found {len(unique_networks)} nearby WiFi networks:")
        print()
        
        for i, network in enumerate(networks, 1):
            ssid = network.get('ssid', 'Unknown')
            auth = network.get('authentication', 'Unknown')
            signal = network.get('signal', 'Unknown')
            
            # Determine security status
            if 'none' in auth.lower() or 'open' in auth.lower():
                security_icon = "🔓"
                security_status = "OPEN (Unsecured)"
                risk_level = "HIGH"
            elif 'wpa' in auth.lower() or 'wep' in auth.lower():
                security_icon = "🔒"
                security_status = "PROTECTED"
                risk_level = "LOW"
            else:
                security_icon = "❓"
                security_status = "UNKNOWN"
                risk_level = "UNKNOWN"
            
            print(f"{i:2d}. {security_icon} {ssid}")
            print(f"    🔐 Security: {security_status}")
            print(f"    📡 Signal: {signal}")
            print(f"    🎯 Risk Level: {risk_level}")
            print()
        
        # Security analysis
        open_networks = [n for n in networks if 'none' in n.get('authentication', '').lower() or 'open' in n.get('authentication', '').lower()]
        
        print("🔒 Security Analysis:")
        print("-" * 40)
        print(f"• Total networks found: {len(networks)}")
        print(f"• Open networks: {len(open_networks)}")
        print(f"• Protected networks: {len(networks) - len(open_networks)}")
        print()
        
        if open_networks:
            print("⚠️  WARNING: Open networks detected!")
            print("   These could be:")
            print("   • Legitimate public WiFi")
            print("   • Evil twin attacks (cloned networks)")
            print("   • Rogue access points")
            print("   • ARP spoofing attempts")
            print()
            print("🔍 Recommendations:")
            print("• Avoid connecting to open networks")
            print("• Verify network names with legitimate sources")
            print("• Use VPN when connecting to public WiFi")
            print("• Monitor for duplicate network names")
        
        print("="*80)
        
    except Exception as e:
        print(f"❌ Error scanning WiFi networks: {e}")

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
                import socket
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

def show_menu():
    """Display the main menu"""
    print("📋 Available Options:")
    print("="*30)
    print("1. 📶 Check Current WiFi Info")
    print("2. 🔍 Check Suspicious DNS Queries")
    print("3. 🛣️  Check Suspicious Routing Entries")
    print("4. 🔌 Check Unauthorized Network Adapters")
    print("5. 📁 Scan Network for FTP Servers")
    print("6. 📡 Scan Nearby WiFi Networks")
    print("7. 🚫 Manage Ignore List")
    print("8. 🚪 Exit")
    print("="*30)

def main():
    """Main function"""
    color = set_random_color()
    
    while True:
        print_banner()
        show_menu()
        
        try:
            choice = input("🔢 Enter your choice (1-8): ").strip()
            
            if choice == '1':
                print()
                check_current_wifi_info()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '2':
                print()
                check_suspicious_dns_queries()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '3':
                print()
                check_suspicious_routing_entries()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '4':
                print()
                check_unauthorized_network_adapters()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '5':
                print()
                scan_ftp_servers()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '6':
                print()
                scan_nearby_wifis()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '7':
                print()
                manage_ignore_list()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '8':
                print("👋 Thank you for using GeckoWifi!")
                reset_color()
                break
            
            else:
                print("⚠️  Invalid choice. Please enter 1, 2, 3, 4, 5, 6, 7, or 8.")
                time.sleep(2)
                os.system('cls' if platform.system() == "Windows" else 'clear')
        
        except KeyboardInterrupt:
            print("\n👋 Thank you for using GeckoWifi!")
            reset_color()
            break
        except Exception as e:
            print(f"❌ An error occurred: {str(e)}")
            time.sleep(2)
            os.system('cls' if platform.system() == "Windows" else 'clear')

if __name__ == "__main__":
    main() 