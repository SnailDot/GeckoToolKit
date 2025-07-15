#!/usr/bin/env python3
"""
GeckoWifi.py - WiFi Security Assessment Tool
A comprehensive tool for checking WiFi connectivity and security for laptop handovers.
"""

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

def show_menu():
    """Display the main menu"""
    print("📋 Available Options:")
    print("="*30)
    print("1. 📶 Check Current WiFi Info")
    print("2. 🔍 Check Suspicious DNS Queries")
    print("3. 🛣️  Check Suspicious Routing Entries")
    print("4. 🔌 Check Unauthorized Network Adapters")
    print("5. 🚪 Exit")
    print("="*30)

def main():
    """Main function"""
    color = set_random_color()
    
    while True:
        print_banner()
        show_menu()
        
        try:
            choice = input("🔢 Enter your choice (1-5): ").strip()
            
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
                print("👋 Thank you for using GeckoWifi!")
                reset_color()
                break
            
            else:
                print("⚠️  Invalid choice. Please enter 1, 2, 3, 4, or 5.")
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