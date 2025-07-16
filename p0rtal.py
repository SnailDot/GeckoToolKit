#!/usr/bin/env python3
"""
P0rtal - Network Connection Tool
A Python terminal-based script for handling SSH, Telnet, and other network connections.
"""

import sys
import os
import subprocess
import platform


# Menu options constant with proper formatting
MENU_OPTIONS = {
    1: "Connect to SSH",
    2: "Connect to Telnet", 
    3: "Open/Close SSH on this device",
    4: "Open Telnet on this device",
    5: "Check current SSH status",
    6: "Check Telnet status",
    7: "Exit"
}


def display_banner():
    """Display the ASCII art banner for p0rtal."""
    banner = """
    ██████╗  ██████╗ ██████╗ ████████╗ █████╗ ██╗     
    ██╔══██╗██╔═████╗██╔══██╗╚══██╔══╝██╔══██╗██║     
    ██████╔╝██║██╔██║██████╔╝   ██║   ███████║██║     
    ██╔═══╝ ████╔╝██║██╔══██╗   ██║   ██╔══██║██║     
    ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
    
    Network Connection Tool
    """
    print(banner)


def display_menu():
    """Display the main menu options."""
    print("\n" + "="*50)
    print("Please select an option:")
    print("="*50)
    
    for option_num, option_text in MENU_OPTIONS.items():
        print(f"{option_num}. {option_text}")
    
    print("="*50)


def check_ssh_status():
    """Check if SSH service is running and display SSH profiles."""
    print("\n" + "="*50)
    print("SSH STATUS CHECK")
    print("="*50)
    
    # Check SSH service status
    try:
        system = platform.system().lower()
        
        if system == "windows":
            # Check OpenSSH Server service on Windows
            try:
                result = subprocess.run(
                    ["sc", "query", "sshd"], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                if result.returncode == 0 and "RUNNING" in result.stdout:
                    print("✓ SSH Server is RUNNING on this device")
                    
                    # Try to get SSH server port
                    try:
                        port_result = subprocess.run(
                            ["netstat", "-an"], 
                            capture_output=True, 
                            text=True, 
                            timeout=10
                        )
                        if ":22 " in port_result.stdout:
                            print("  - SSH Server listening on port 22")
                        else:
                            print("  - SSH Server running (port not detected)")
                    except Exception:
                        print("  - SSH Server running (port check failed)")
                        
                else:
                    print("✗ SSH Server is NOT running on this device")
                    
            except subprocess.TimeoutExpired:
                print("⚠ SSH status check timed out")
            except Exception as e:
                print(f"⚠ Could not check SSH service status: {e}")
                
        else:
            # Check SSH service on Unix-like systems
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", "ssh"], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                if result.returncode == 0 and "active" in result.stdout:
                    print("✓ SSH Server is RUNNING on this device")
                else:
                    # Try alternative service names
                    alt_result = subprocess.run(
                        ["systemctl", "is-active", "sshd"], 
                        capture_output=True, 
                        text=True, 
                        timeout=10
                    )
                    if alt_result.returncode == 0 and "active" in alt_result.stdout:
                        print("✓ SSH Server is RUNNING on this device")
                    else:
                        print("✗ SSH Server is NOT running on this device")
                        
            except subprocess.TimeoutExpired:
                print("⚠ SSH status check timed out")
            except FileNotFoundError:
                print("⚠ systemctl not found - cannot check SSH status")
            except Exception as e:
                print(f"⚠ Could not check SSH service status: {e}")
                
    except Exception as e:
        print(f"⚠ Error checking SSH status: {e}")
    
    print("\n" + "-"*50)
    print("SSH PROFILES")
    print("-"*50)
    
    # Check for SSH config and known hosts
    try:
        ssh_dir = os.path.expanduser("~/.ssh")
        config_file = os.path.join(ssh_dir, "config")
        known_hosts_file = os.path.join(ssh_dir, "known_hosts")
        
        if os.path.exists(ssh_dir):
            print(f"SSH directory found: {ssh_dir}")
            
            # Check SSH config file
            if os.path.exists(config_file):
                print(f"\n📁 SSH Config file found: {config_file}")
                try:
                    with open(config_file, 'r') as f:
                        config_content = f.read()
                        
                    # Parse basic host entries
                    hosts = []
                    lines = config_content.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line.startswith('Host ') and not line.startswith('Host *'):
                            host_name = line.replace('Host ', '').strip()
                            if host_name:
                                hosts.append(host_name)
                    
                    if hosts:
                        print("  SSH Host profiles found:")
                        for host in hosts[:10]:  # Limit to first 10
                            print(f"    - {host}")
                        if len(hosts) > 10:
                            print(f"    ... and {len(hosts) - 10} more")
                    else:
                        print("  No host profiles found in config")
                        
                except Exception as e:
                    print(f"  ⚠ Could not read SSH config: {e}")
            else:
                print("📄 No SSH config file found")
            
            # Check known hosts
            if os.path.exists(known_hosts_file):
                print(f"\n📁 Known hosts file found: {known_hosts_file}")
                try:
                    with open(known_hosts_file, 'r') as f:
                        lines = f.readlines()
                    
                    if lines:
                        print(f"  {len(lines)} known host entries found")
                        # Show first few hosts (without revealing full entries for security)
                        sample_hosts = []
                        for line in lines[:5]:
                            if line.strip() and not line.startswith('#'):
                                # Extract hostname (first part before space)
                                parts = line.strip().split()
                                if parts:
                                    host_part = parts[0]
                                    # Remove port info and show just hostname
                                    if ',' in host_part:
                                        host_part = host_part.split(',')[0]
                                    if ':' in host_part and not host_part.startswith('['):
                                        host_part = host_part.split(':')[0]
                                    sample_hosts.append(host_part)
                        
                        if sample_hosts:
                            print("  Recent connections to:")
                            for host in sample_hosts:
                                print(f"    - {host}")
                    else:
                        print("  Known hosts file is empty")
                        
                except Exception as e:
                    print(f"  ⚠ Could not read known hosts: {e}")
            else:
                print("📄 No known hosts file found")
                
            # Check for SSH keys
            key_files = ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519']
            found_keys = []
            for key_file in key_files:
                key_path = os.path.join(ssh_dir, key_file)
                if os.path.exists(key_path):
                    found_keys.append(key_file)
            
            if found_keys:
                print(f"\n🔑 SSH Keys found:")
                for key in found_keys:
                    print(f"    - {key}")
            else:
                print("\n🔑 No SSH keys found")
                
        else:
            print("📂 No SSH directory found (~/.ssh)")
            print("   SSH has not been configured on this system")
            
    except Exception as e:
        print(f"⚠ Error checking SSH profiles: {e}")
    
    print("\n" + "="*50)


def check_telnet_status():
    """Check if Telnet service is running and display Telnet profiles."""
    print("\n" + "="*50)
    print("TELNET STATUS CHECK")
    print("="*50)
    
    # Check Telnet service status
    try:
        system = platform.system().lower()
        
        if system == "windows":
            # Check Telnet Server service on Windows
            try:
                result = subprocess.run(
                    ["sc", "query", "tlntsvr"], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                if result.returncode == 0 and "RUNNING" in result.stdout:
                    print("✓ Telnet Server is RUNNING on this device")
                    
                    # Try to get Telnet server port
                    try:
                        port_result = subprocess.run(
                            ["netstat", "-an"], 
                            capture_output=True, 
                            text=True, 
                            timeout=10
                        )
                        if ":23 " in port_result.stdout:
                            print("  - Telnet Server listening on port 23")
                        else:
                            print("  - Telnet Server running (port not detected)")
                    except Exception:
                        print("  - Telnet Server running (port check failed)")
                        
                else:
                    print("✗ Telnet Server is NOT running on this device")
                    
                # Check if Telnet Client is enabled
                try:
                    client_result = subprocess.run(
                        ["dism", "/online", "/get-featureinfo", "/featurename:TelnetClient"], 
                        capture_output=True, 
                        text=True, 
                        timeout=10
                    )
                    if "State : Enabled" in client_result.stdout:
                        print("✓ Telnet Client is ENABLED on this device")
                    else:
                        print("✗ Telnet Client is NOT enabled on this device")
                except Exception:
                    print("⚠ Could not check Telnet Client status")
                    
            except subprocess.TimeoutExpired:
                print("⚠ Telnet status check timed out")
            except Exception as e:
                print(f"⚠ Could not check Telnet service status: {e}")
                
        else:
            # Check Telnet service on Unix-like systems
            try:
                # Check if telnetd is running
                result = subprocess.run(
                    ["pgrep", "-f", "telnetd"], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    print("✓ Telnet daemon (telnetd) is RUNNING on this device")
                else:
                    print("✗ Telnet daemon (telnetd) is NOT running on this device")
                
                # Check if telnet client is installed
                client_result = subprocess.run(
                    ["which", "telnet"], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                if client_result.returncode == 0:
                    print("✓ Telnet client is INSTALLED on this device")
                    print(f"  - Location: {client_result.stdout.strip()}")
                else:
                    print("✗ Telnet client is NOT installed on this device")
                        
            except subprocess.TimeoutExpired:
                print("⚠ Telnet status check timed out")
            except FileNotFoundError:
                print("⚠ Required commands not found - cannot check Telnet status")
            except Exception as e:
                print(f"⚠ Could not check Telnet service status: {e}")
                
    except Exception as e:
        print(f"⚠ Error checking Telnet status: {e}")
    
    # Check Telnet port status
    print("\n" + "-"*50)
    print("TELNET PORT STATUS")
    print("-"*50)
    
    try:
        # Check if port 23 is listening
        port_result = subprocess.run(
            ["netstat", "-an"], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        
        if port_result.returncode == 0:
            lines = port_result.stdout.split('\n')
            telnet_ports = []
            
            for line in lines:
                if ':23 ' in line and ('LISTEN' in line or 'LISTENING' in line):
                    telnet_ports.append(line.strip())
            
            if telnet_ports:
                print("✓ Telnet ports are OPEN and listening:")
                for port_line in telnet_ports:
                    print(f"  - {port_line}")
            else:
                print("✗ No Telnet ports (port 23) are currently listening")
                
                # Check for any other telnet-related ports
                other_telnet_ports = []
                for line in lines:
                    if 'telnet' in line.lower() or ':992' in line:  # 992 is secure telnet
                        other_telnet_ports.append(line.strip())
                
                if other_telnet_ports:
                    print("  Other Telnet-related ports found:")
                    for port_line in other_telnet_ports:
                        print(f"    - {port_line}")
        else:
            print("⚠ Could not check port status")
            
    except Exception as e:
        print(f"⚠ Error checking Telnet port status: {e}")
    
    print("\n" + "-"*50)
    print("TELNET PROFILES")
    print("-"*50)
    
    # Check for Telnet configuration files and profiles
    try:
        # Check common Telnet configuration locations
        telnet_configs = [
            "/etc/xinetd.d/telnet",
            "/etc/inetd.conf",
            "~/.telnetrc",
            "/etc/telnetrc"
        ]
        
        found_configs = []
        for config_path in telnet_configs:
            expanded_path = os.path.expanduser(config_path)
            if os.path.exists(expanded_path):
                found_configs.append(expanded_path)
        
        if found_configs:
            print("📁 Telnet configuration files found:")
            for config in found_configs:
                print(f"  - {config}")
                
                # Try to read basic info from config files
                try:
                    if os.path.isfile(config):
                        with open(config, 'r') as f:
                            content = f.read()
                            lines = content.split('\n')
                            relevant_lines = [line.strip() for line in lines[:10] 
                                            if line.strip() and not line.strip().startswith('#')]
                            if relevant_lines:
                                print(f"    Configuration preview:")
                                for line in relevant_lines[:3]:  # Show first 3 relevant lines
                                    print(f"      {line}")
                                if len(relevant_lines) > 3:
                                    print(f"      ... and {len(relevant_lines) - 3} more lines")
                except Exception as e:
                    print(f"    ⚠ Could not read config file: {e}")
        else:
            print("📄 No standard Telnet configuration files found")
        
        # Check for Telnet history or connection logs
        history_files = [
            "~/.bash_history",
            "~/.zsh_history",
            "~/.history"
        ]
        
        telnet_connections = []
        for history_file in history_files:
            expanded_path = os.path.expanduser(history_file)
            if os.path.exists(expanded_path):
                try:
                    with open(expanded_path, 'r') as f:
                        lines = f.readlines()
                        for line in lines[-100:]:  # Check last 100 commands
                            if 'telnet ' in line.lower():
                                clean_line = line.strip()
                                if clean_line not in telnet_connections:
                                    telnet_connections.append(clean_line)
                except Exception:
                    continue
        
        if telnet_connections:
            print(f"\n📋 Recent Telnet connections found in history:")
            for connection in telnet_connections[-5:]:  # Show last 5
                print(f"  - {connection}")
            if len(telnet_connections) > 5:
                print(f"  ... and {len(telnet_connections) - 5} more in history")
        else:
            print("\n📋 No recent Telnet connections found in command history")
            
        # Note about Telnet profiles
        print(f"\n💡 Note: Unlike SSH, Telnet typically doesn't use saved profiles.")
        print(f"   Connections are usually made directly with: telnet <hostname> [port]")
            
    except Exception as e:
        print(f"⚠ Error checking Telnet profiles: {e}")
    
    print("\n" + "="*50)


def is_ssh_running():
    """Check if SSH service is currently running."""
    try:
        system = platform.system().lower()
        
        if system == "windows":
            result = subprocess.run(
                ["sc", "query", "sshd"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            return result.returncode == 0 and "RUNNING" in result.stdout
        else:
            # Try ssh first, then sshd
            result = subprocess.run(
                ["systemctl", "is-active", "ssh"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0 and "active" in result.stdout:
                return True
            
            alt_result = subprocess.run(
                ["systemctl", "is-active", "sshd"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            return alt_result.returncode == 0 and "active" in alt_result.stdout
            
    except Exception:
        return False


def get_ssh_profiles():
    """Get list of SSH profiles from config file."""
    profiles = []
    try:
        ssh_dir = os.path.expanduser("~/.ssh")
        config_file = os.path.join(ssh_dir, "config")
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config_content = f.read()
                
            lines = config_content.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('Host ') and not line.startswith('Host *'):
                    host_name = line.replace('Host ', '').strip()
                    if host_name:
                        profiles.append(host_name)
                        
    except Exception as e:
        print(f"⚠ Error reading SSH profiles: {e}")
    
    return profiles


def enable_windows_openssh():
    """Enable OpenSSH Server on Windows using built-in features."""
    try:
        print("🔄 Enabling OpenSSH Server feature on Windows...")
        
        # Try using PowerShell to enable OpenSSH Server
        powershell_cmd = [
            "powershell", "-Command",
            "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
        ]
        
        result = subprocess.run(
            powershell_cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            print("✓ OpenSSH Server feature enabled successfully")
            
            # Start the SSH service
            start_result = subprocess.run(
                ["sc", "start", "sshd"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if start_result.returncode == 0:
                print("✓ SSH Server started successfully")
                
                # Set service to start automatically
                auto_result = subprocess.run(
                    ["sc", "config", "sshd", "start=", "auto"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if auto_result.returncode == 0:
                    print("✓ SSH Server set to start automatically")
                
                return True
            else:
                print(f"⚠ SSH Server enabled but failed to start: {start_result.stderr}")
                return False
        else:
            print(f"✗ Failed to enable OpenSSH Server: {result.stderr}")
            print("💡 You may need to run as Administrator")
            return False
            
    except subprocess.TimeoutExpired:
        print("⚠ OpenSSH Server installation timed out")
        return False
    except Exception as e:
        print(f"⚠ Error enabling OpenSSH Server: {e}")
        return False


def install_linux_openssh():
    """Install OpenSSH Server on Linux using built-in package managers."""
    try:
        print("🔄 Installing OpenSSH Server on Linux...")
        
        # Detect Linux distribution and use appropriate package manager
        distro_info = ""
        try:
            with open("/etc/os-release", "r") as f:
                distro_info = f.read().lower()
        except:
            pass
        
        install_commands = []
        
        if "ubuntu" in distro_info or "debian" in distro_info:
            install_commands = [
                ["sudo", "apt", "update"],
                ["sudo", "apt", "install", "-y", "openssh-server"]
            ]
        elif "centos" in distro_info or "rhel" in distro_info or "fedora" in distro_info:
            if "fedora" in distro_info:
                install_commands = [
                    ["sudo", "dnf", "install", "-y", "openssh-server"]
                ]
            else:
                install_commands = [
                    ["sudo", "yum", "install", "-y", "openssh-server"]
                ]
        elif "arch" in distro_info:
            install_commands = [
                ["sudo", "pacman", "-S", "--noconfirm", "openssh"]
            ]
        else:
            print("⚠ Unknown Linux distribution. Please install openssh-server manually:")
            print("  Ubuntu/Debian: sudo apt install openssh-server")
            print("  CentOS/RHEL: sudo yum install openssh-server")
            print("  Fedora: sudo dnf install openssh-server")
            print("  Arch: sudo pacman -S openssh")
            return False
        
        # Execute installation commands
        for cmd in install_commands:
            print(f"🔄 Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                print(f"✗ Command failed: {result.stderr}")
                return False
        
        print("✓ OpenSSH Server installed successfully")
        
        # Enable and start the service
        service_name = "ssh" if "ubuntu" in distro_info or "debian" in distro_info else "sshd"
        
        enable_result = subprocess.run(
            ["sudo", "systemctl", "enable", service_name],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        start_result = subprocess.run(
            ["sudo", "systemctl", "start", service_name],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if enable_result.returncode == 0 and start_result.returncode == 0:
            print("✓ SSH service enabled and started successfully")
            return True
        else:
            print("⚠ SSH installed but service configuration may have issues")
            return False
            
    except subprocess.TimeoutExpired:
        print("⚠ SSH installation timed out")
        return False
    except Exception as e:
        print(f"⚠ Error installing SSH server: {e}")
        return False


def toggle_ssh_service():
    """Toggle SSH service on/off using built-in system features."""
    try:
        system = platform.system().lower()
        ssh_running = is_ssh_running()
        
        if system == "windows":
            if ssh_running:
                print("🔄 Stopping SSH Server...")
                result = subprocess.run(
                    ["sc", "stop", "sshd"], 
                    capture_output=True, 
                    text=True, 
                    timeout=30
                )
                if result.returncode == 0:
                    print("✓ SSH Server stopped successfully")
                    return False
                else:
                    print(f"✗ Failed to stop SSH Server: {result.stderr}")
                    return ssh_running
            else:
                # Try to start SSH service first
                print("🔄 Attempting to start SSH Server...")
                start_result = subprocess.run(
                    ["sc", "start", "sshd"], 
                    capture_output=True, 
                    text=True, 
                    timeout=30
                )
                
                if start_result.returncode == 0:
                    print("✓ SSH Server started successfully")
                    return True
                else:
                    # SSH service doesn't exist, try to enable OpenSSH Server feature
                    print("⚠ SSH Server not found. Attempting to enable OpenSSH Server feature...")
                    return enable_windows_openssh()
        else:
            # Unix-like systems
            service_name = "ssh"  # Default to ssh
            
            # Check which service exists
            ssh_check = subprocess.run(
                ["systemctl", "list-unit-files", "ssh.service"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            sshd_check = subprocess.run(
                ["systemctl", "list-unit-files", "sshd.service"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            if "sshd.service" in sshd_check.stdout:
                service_name = "sshd"
            elif "ssh.service" not in ssh_check.stdout:
                # Neither service exists, try to install
                print("⚠ SSH Server not found. Attempting to install OpenSSH Server...")
                if install_linux_openssh():
                    return True
                else:
                    return False
            
            if ssh_running:
                print("🔄 Stopping SSH service...")
                result = subprocess.run(
                    ["sudo", "systemctl", "stop", service_name], 
                    capture_output=True, 
                    text=True, 
                    timeout=30
                )
                if result.returncode == 0:
                    print("✓ SSH service stopped successfully")
                    return False
                else:
                    print(f"✗ Failed to stop SSH service: {result.stderr}")
                    return ssh_running
            else:
                print("🔄 Starting SSH service...")
                result = subprocess.run(
                    ["sudo", "systemctl", "start", service_name], 
                    capture_output=True, 
                    text=True, 
                    timeout=30
                )
                if result.returncode == 0:
                    print("✓ SSH service started successfully")
                    return True
                else:
                    print(f"✗ Failed to start SSH service: {result.stderr}")
                    return ssh_running
                    
    except subprocess.TimeoutExpired:
        print("⚠ SSH service toggle timed out")
        return ssh_running
    except Exception as e:
        print(f"⚠ Error toggling SSH service: {e}")
        return ssh_running


def create_ssh_profile():
    """Create a new SSH profile."""
    print("\n" + "="*50)
    print("CREATE NEW SSH PROFILE")
    print("="*50)
    
    try:
        # Get profile details from user
        profile_name = input("Enter profile name: ").strip()
        if not profile_name:
            print("✗ Profile name cannot be empty")
            return None
            
        hostname = input("Enter hostname/IP address: ").strip()
        if not hostname:
            print("✗ Hostname cannot be empty")
            return None
            
        username = input("Enter username: ").strip()
        if not username:
            print("✗ Username cannot be empty")
            return None
            
        port = input("Enter port (default 22): ").strip()
        if not port:
            port = "22"
        
        # Validate port
        try:
            port_num = int(port)
            if port_num < 1 or port_num > 65535:
                print("✗ Port must be between 1 and 65535")
                return None
        except ValueError:
            print("✗ Port must be a valid number")
            return None
        
        # Create SSH directory if it doesn't exist
        ssh_dir = os.path.expanduser("~/.ssh")
        if not os.path.exists(ssh_dir):
            os.makedirs(ssh_dir, mode=0o700)
            print(f"📁 Created SSH directory: {ssh_dir}")
        
        # Create or append to SSH config
        config_file = os.path.join(ssh_dir, "config")
        config_entry = f"""
Host {profile_name}
    HostName {hostname}
    User {username}
    Port {port}
"""
        
        with open(config_file, 'a') as f:
            f.write(config_entry)
        
        # Set proper permissions
        os.chmod(config_file, 0o600)
        
        print(f"✓ SSH profile '{profile_name}' created successfully")
        print(f"  - Hostname: {hostname}")
        print(f"  - Username: {username}")
        print(f"  - Port: {port}")
        
        return profile_name
        
    except Exception as e:
        print(f"✗ Error creating SSH profile: {e}")
        return None


def connect_to_ssh_profile(profile_name):
    """Connect to SSH using a profile."""
    try:
        print(f"\n🔄 Connecting to SSH profile '{profile_name}'...")
        
        # Use ssh command with the profile
        result = subprocess.run(
            ["ssh", profile_name], 
            timeout=30
        )
        
        if result.returncode == 0:
            print(f"✓ SSH connection to '{profile_name}' completed")
        else:
            print(f"⚠ SSH connection to '{profile_name}' ended with code {result.returncode}")
            
    except subprocess.TimeoutExpired:
        print(f"⚠ SSH connection to '{profile_name}' timed out")
    except FileNotFoundError:
        print("✗ SSH client not found. Please install SSH client first.")
    except KeyboardInterrupt:
        print(f"\n⚠ SSH connection to '{profile_name}' interrupted by user")
    except Exception as e:
        print(f"✗ Error connecting to SSH profile '{profile_name}': {e}")


def open_close_ssh():
    """Handle SSH toggle and profile management."""
    print("\n" + "="*50)
    print("SSH SERVICE MANAGEMENT")
    print("="*50)
    
    # Check current SSH status
    ssh_running = is_ssh_running()
    
    if ssh_running:
        print("✓ SSH Server is currently RUNNING")
    else:
        print("✗ SSH Server is currently NOT running")
    
    # Toggle SSH service
    print(f"\n🔄 Toggling SSH service...")
    new_status = toggle_ssh_service()
    
    if new_status != ssh_running:
        if new_status:
            print("✅ SSH Server is now RUNNING")
        else:
            print("🔴 SSH Server is now STOPPED")
            return  # If SSH is stopped, no need to handle profiles
    else:
        print("⚠ SSH service status unchanged")
        if not new_status:
            return  # If SSH failed to start, don't continue with profiles
    
    # Handle SSH profiles if SSH is running
    print("\n" + "-"*50)
    print("SSH PROFILE MANAGEMENT")
    print("-"*50)
    
    profiles = get_ssh_profiles()
    
    if profiles:
        print("📋 Available SSH profiles:")
        for i, profile in enumerate(profiles, 1):
            print(f"  {i}. {profile}")
        
        print(f"  {len(profiles) + 1}. Create new profile")
        print(f"  {len(profiles) + 2}. Skip profile selection")
        
        while True:
            try:
                choice = input(f"\nSelect profile (1-{len(profiles) + 2}): ").strip()
                
                if not choice:
                    continue
                
                choice_num = int(choice)
                
                if 1 <= choice_num <= len(profiles):
                    # Connect to existing profile
                    selected_profile = profiles[choice_num - 1]
                    connect_to_ssh_profile(selected_profile)
                    break
                elif choice_num == len(profiles) + 1:
                    # Create new profile
                    new_profile = create_ssh_profile()
                    if new_profile:
                        connect_choice = input(f"\nConnect to '{new_profile}' now? (y/n): ").strip().lower()
                        if connect_choice in ['y', 'yes']:
                            connect_to_ssh_profile(new_profile)
                    break
                elif choice_num == len(profiles) + 2:
                    # Skip
                    print("⏭ Skipping profile selection")
                    break
                else:
                    print(f"✗ Please enter a number between 1 and {len(profiles) + 2}")
                    
            except ValueError:
                print("✗ Please enter a valid number")
            except KeyboardInterrupt:
                print("\n⚠ Profile selection interrupted")
                break
    else:
        print("📄 No SSH profiles found")
        create_choice = input("Create a new SSH profile? (y/n): ").strip().lower()
        
        if create_choice in ['y', 'yes']:
            new_profile = create_ssh_profile()
            if new_profile:
                connect_choice = input(f"\nConnect to '{new_profile}' now? (y/n): ").strip().lower()
                if connect_choice in ['y', 'yes']:
                    connect_to_ssh_profile(new_profile)
        else:
            print("⏭ Skipping profile creation")
    
    print("\n" + "="*50)


def get_user_choice():
    """Get and validate user input for menu selection."""
    while True:
        try:
            choice = input("\nEnter your choice: ").strip()
            
            # Check if input is empty
            if not choice:
                print("Error: Please enter a valid option (1-7).")
                continue
            
            # Check for common invalid inputs
            if choice.lower() in ['q', 'quit', 'exit']:
                print("To exit, please select option 7 from the menu.")
                continue
            
            # Convert to integer
            choice_num = int(choice)
            
            # Validate range with more specific error messages
            if choice_num in MENU_OPTIONS:
                return choice_num
            elif choice_num < 1:
                print("Error: Please enter a positive number between 1 and 7.")
            elif choice_num > len(MENU_OPTIONS):
                print(f"Error: Please enter a number between 1 and {len(MENU_OPTIONS)}.")
            else:
                print(f"Error: Invalid selection. Please choose from options 1-{len(MENU_OPTIONS)}.")
                
        except ValueError as e:
            # Handle specific ValueError cases
            if "invalid literal for int()" in str(e):
                print("Error: Please enter a valid number (1-7), not letters or symbols.")
            else:
                print("Error: Invalid input format. Please enter a number between 1 and 7.")
        except KeyboardInterrupt:
            print("\n\nInterrupted by user. Exiting p0rtal. Goodbye!")
            sys.exit(0)
        except EOFError:
            print("\n\nEnd of input detected. Exiting p0rtal. Goodbye!")
            sys.exit(0)
        except Exception as e:
            print(f"Error: An unexpected error occurred while processing input: {e}")
            print("Please try again with a number between 1 and 7.")


def handle_menu_selection(choice):
    """Route user menu selection to appropriate handler function."""
    try:
        if choice == 1:
            # Connect to SSH
            try:
                connect_ssh()
            except NameError:
                print("SSH connection feature is not yet implemented.")
            except Exception as e:
                print(f"Error: Failed to establish SSH connection: {e}")
        elif choice == 2:
            # Connect to Telnet
            try:
                connect_telnet()
            except NameError:
                print("Telnet connection feature is not yet implemented.")
            except Exception as e:
                print(f"Error: Failed to establish Telnet connection: {e}")
        elif choice == 3:
            # Open/Close SSH on this device
            try:
                open_close_ssh()
            except Exception as e:
                print(f"Error: Failed to manage SSH service: {e}")
        elif choice == 4:
            # Open Telnet server on this device
            try:
                open_telnet_server()
            except NameError:
                print("Telnet server feature is not yet implemented.")
            except Exception as e:
                print(f"Error: Failed to start Telnet server: {e}")
        elif choice == 5:
            # Check current SSH status
            try:
                check_ssh_status()
            except Exception as e:
                print(f"Error: Failed to check SSH status: {e}")
        elif choice == 6:
            # Check Telnet status
            try:
                check_telnet_status()
            except Exception as e:
                print(f"Error: Failed to check Telnet status: {e}")
        elif choice == 7:
            # Exit application
            print("\nExiting p0rtal. Goodbye!")
            return False
        else:
            # This should not happen due to input validation, but handle it anyway
            print(f"Error: Invalid menu selection: {choice}")
            print("Please select a valid option from the menu.")
            
    except KeyboardInterrupt:
        print("\n\nOperation interrupted by user.")
        return True  # Continue running, don't exit
    except Exception as e:
        print(f"Error: An unexpected error occurred while processing menu selection: {e}")
        print("Returning to main menu...")
    
    return True


def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        system = platform.system().lower()
        
        if system == "windows":
            # Check if running as administrator on Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            # Check if running as root on Unix-like systems
            return os.geteuid() == 0
    except Exception:
        return False


def request_admin_privileges():
    """Request administrator privileges and restart the script if needed."""
    system = platform.system().lower()
    
    if system == "windows":
        try:
            import ctypes
            
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("🔐 Administrator privileges required for SSH/Telnet server management")
                print("🔄 Requesting administrator privileges...")
                
                # Re-run the script with admin privileges
                ctypes.windll.shell32.ShellExecuteW(
                    None, 
                    "runas", 
                    sys.executable, 
                    " ".join(sys.argv), 
                    None, 
                    1
                )
                
                print("✓ Please approve the administrator request in the popup window")
                print("⚠ If no popup appeared, please run this script as Administrator")
                input("Press Enter to exit...")
                sys.exit(0)
            else:
                print("✓ Running with administrator privileges")
                
        except Exception as e:
            print(f"⚠ Could not request administrator privileges: {e}")
            print("💡 Please run this script as Administrator for full functionality")
            
            # Ask user if they want to continue without admin privileges
            choice = input("Continue without administrator privileges? (y/n): ").strip().lower()
            if choice not in ['y', 'yes']:
                print("Exiting p0rtal. Please run as Administrator.")
                sys.exit(0)
            else:
                print("⚠ Some features may not work without administrator privileges")
                
    else:
        # Unix-like systems
        if os.geteuid() != 0:
            print("🔐 Root privileges required for SSH/Telnet server management")
            print("💡 Please run this script with sudo:")
            print(f"   sudo python3 {sys.argv[0]}")
            
            # Ask user if they want to continue without root privileges
            choice = input("Continue without root privileges? (y/n): ").strip().lower()
            if choice not in ['y', 'yes']:
                print("Exiting p0rtal. Please run with sudo.")
                sys.exit(0)
            else:
                print("⚠ Some features may not work without root privileges")
        else:
            print("✓ Running with root privileges")


def main():
    """Main function with application loop for menu display and input handling."""
    # Request administrator privileges first
    request_admin_privileges()
    
    # Clear screen for better presentation
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Display the banner
    display_banner()
    
    # Main application loop
    running = True
    while running:
        try:
            # Display menu and get user choice
            display_menu()
            choice = get_user_choice()
            
            # Handle the menu selection
            running = handle_menu_selection(choice)
            
            # If not exiting, pause before showing menu again
            if running:
                input("\nPress Enter to continue...")
                # Clear screen for next iteration
                os.system('cls' if os.name == 'nt' else 'clear')
                display_banner()
                
        except KeyboardInterrupt:
            print("\n\nExiting p0rtal. Goodbye!")
            break
        except Exception as e:
            print(f"\nError: An unexpected error occurred: {e}")
            print("Returning to main menu...")
            input("Press Enter to continue...")
            # Clear screen and redisplay banner
            os.system('cls' if os.name == 'nt' else 'clear')
            display_banner()


if __name__ == "__main__":
    main()