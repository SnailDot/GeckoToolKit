
import subprocess
import platform
import os
import sys
import re
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
    try:
        result = subprocess.run(command, shell=shell, capture_output=True, text=True, timeout=30)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)

def check_admin_privileges():
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def scan_port(port):
    if platform.system() == "Windows":
        success, stdout, stderr = run_command(f'netstat -an | findstr :{port}')
        if success and stdout.strip():
            lines = stdout.strip().split('\n')
            for line in lines:
                if f':{port}' in line and 'LISTENING' in line:
                    return True, line.strip()
            return False, "Port found but not listening"
        else:
            return False, "Port not found"
    else:
        success, stdout, stderr = run_command(f'netstat -tuln | grep :{port}')
        if success and stdout.strip():
            return True, stdout.strip()
        else:
            return False, "Port not found"

def check_firewall_rules(port):
    if platform.system() == "Windows":
        success, stdout, stderr = run_command(f'netsh advfirewall firewall show rule name="Block Port {port} TCP Inbound"')
        if success and "No rules match the specified criteria" not in stdout:
            return True
        return False
    elif platform.system() == "Linux":
        success, stdout, stderr = run_command(f'iptables -L INPUT -n | grep "dpt:{port}"')
        if success and stdout.strip():
            if "DROP" in stdout:
                return True
        return False
    return False

def is_port_actually_blocked(port):
    return check_firewall_rules(port)

def get_port_status(port):
    is_listening, details = scan_port(port)
    is_blocked = is_port_actually_blocked(port)
    if is_listening:
        if platform.system() == "Windows":
            success, stdout, stderr = run_command(f'netstat -anob | findstr :{port}')
            if success and stdout.strip():
                details = stdout.strip()
        if is_blocked:
            return False, f"LISTENING but BLOCKED by firewall\n{details}"
        else:
            return True, f"LISTENING and ACCESSIBLE\n{details}"
    else:
        return False, "Not listening"

def block_port_windows(port):
    commands = [
        f'netsh advfirewall firewall add rule name="Block Port {port} TCP Inbound" dir=in action=block protocol=TCP localport={port}',
        f'netsh advfirewall firewall add rule name="Block Port {port} TCP Outbound" dir=out action=block protocol=TCP localport={port}',
        f'netsh advfirewall firewall add rule name="Block Port {port} UDP Inbound" dir=in action=block protocol=UDP localport={port}',
        f'netsh advfirewall firewall add rule name="Block Port {port} UDP Outbound" dir=out action=block protocol=UDP localport={port}'
    ]
    success_count = 0
    for cmd in commands:
        success, stdout, stderr = run_command(cmd)
        if success:
            success_count += 1
    return success_count > 0

def block_port_linux(port):
    commands = [
        f'iptables -A INPUT -p tcp --dport {port} -j DROP',
        f'iptables -A OUTPUT -p tcp --sport {port} -j DROP',
        f'iptables -A INPUT -p udp --dport {port} -j DROP',
        f'iptables -A OUTPUT -p udp --sport {port} -j DROP'
    ]
    success_count = 0
    for cmd in commands:
        success, stdout, stderr = run_command(cmd)
        if success:
            success_count += 1
    return success_count > 0

def unblock_port_windows(port):
    commands = [
        f'netsh advfirewall firewall delete rule name="Block Port {port} TCP Inbound"',
        f'netsh advfirewall firewall delete rule name="Block Port {port} TCP Outbound"',
        f'netsh advfirewall firewall delete rule name="Block Port {port} UDP Inbound"',
        f'netsh advfirewall firewall delete rule name="Block Port {port} UDP Outbound"'
    ]
    success_count = 0
    for cmd in commands:
        success, stdout, stderr = run_command(cmd)
        if success:
            success_count += 1
    return success_count > 0

def unblock_port_linux(port):
    commands = [
        f'iptables -D INPUT -p tcp --dport {port} -j DROP',
        f'iptables -D OUTPUT -p tcp --sport {port} -j DROP',
        f'iptables -D INPUT -p udp --dport {port} -j DROP',
        f'iptables -D OUTPUT -p udp --sport {port} -j DROP'
    ]
    success_count = 0
    for cmd in commands:
        success, stdout, stderr = run_command(cmd)
        if success:
            success_count += 1
    return success_count > 0

def get_port_description(port):
    descriptions = {
        22: "SSH (Secure Remote Access)",
        23: "Telnet (Remote Control)",
        445: "File Sharing (SMB)",
        135: "Windows Services",
        139: "Network Discovery",
        5357: "Printers & Devices",
        4899: "Remote Desktop",
        5631: "Remote Control",
        5000: "Web Services",
        5009: "Remote Access"
    }
    return descriptions.get(port, "Unknown Service")

def scan_all_ports():
    print("\nScanning for open ports...")
    open_ports = []
    
    if platform.system() == "Windows":
        success, stdout, stderr = run_command('netstat -an | findstr LISTENING')
        if success and stdout.strip():
            lines = stdout.strip().split('\n')
            for line in lines:
                try:
                    parts = line.split()
                    if len(parts) >= 2:
                        address_part = parts[1]
                        if ':' in address_part:
                            port_str = address_part.split(':')[-1]
                            port = int(port_str)
                            if port not in open_ports:
                                open_ports.append(port)
                except:
                    continue
    else:
        success, stdout, stderr = run_command('netstat -tuln | grep LISTEN')
        if success and stdout.strip():
            lines = stdout.strip().split('\n')
            for line in lines:
                try:
                    parts = line.split()
                    if len(parts) >= 4:
                        address_part = parts[3]
                        if ':' in address_part:
                            port_str = address_part.split(':')[-1]
                            port = int(port_str)
                            if port not in open_ports:
                                open_ports.append(port)
                except:
                    continue
    
    if open_ports:
        open_ports.sort()
        print(f"\nFound {len(open_ports)} open ports:")
        print("\nPort | Status | Description")
        print("-" * 50)
        
        for port in open_ports:
            is_blocked = is_port_actually_blocked(port)
            description = get_port_description(port)
            
            if is_blocked:
                status = "BLOCKED"
            else:
                status = "OPEN"
            
            print(f"{port:4} | {status:7} | {description}")
    else:
        print("\nNo open ports found.")
    
    print()

def scan_risky_ports():
    risky_ports = [22, 23, 445, 135, 139, 5357, 4899, 5631, 5000, 5009]
    print("\nScanning risky ports...")
    print("\nPort | Status | Description")
    print("-" * 50)
    
    for port in risky_ports:
        is_listening, _ = scan_port(port)
        is_blocked = is_port_actually_blocked(port)
        description = get_port_description(port)
        
        if is_listening:
            if is_blocked:
                status = "BLOCKED"
            else:
                status = "OPEN"
        else:
            status = "CLOSED"
        
        print(f"{port:4} | {status:7} | {description}")
    
    print()

def scan_dangerous_ports():
    dangerous_ports = [22, 23, 4899, 5631, 5009]
    print("\nScanning dangerous ports...")
    print("\nWARNING: If you don't understand what any of these are, they need to be blocked.")
    print("\nPort | Status | Description")
    print("-" * 50)
    
    for port in dangerous_ports:
        is_listening, _ = scan_port(port)
        is_blocked = is_port_actually_blocked(port)
        description = get_port_description(port)
        
        if is_listening:
            if is_blocked:
                status = "BLOCKED"
            else:
                status = "OPEN"
        else:
            status = "CLOSED"
        
        print(f"{port:4} | {status:7} | {description}")
    
    print()

def show_blocked_ports():
    print("\nChecking firewall for blocked ports...")
    blocked = []
    
    if platform.system() == "Windows":
        success, stdout, stderr = run_command('netsh advfirewall firewall show rule name=all')
        if success and stdout.strip():
            lines = stdout.strip().split('\n')
            for line in lines:
                if 'Block Port' in line and 'TCP Inbound' in line:
                    try:
                        port_match = re.search(r'Block Port (\d+) TCP Inbound', line)
                        if port_match:
                            port = int(port_match.group(1))
                            if port not in blocked:
                                blocked.append(port)
                    except:
                        continue
    elif platform.system() == "Linux":
        success, stdout, stderr = run_command('iptables -L INPUT -n | grep DROP')
        if success and stdout.strip():
            lines = stdout.strip().split('\n')
            for line in lines:
                try:
                    port_match = re.search(r'dpt:(\d+)', line)
                    if port_match:
                        port = int(port_match.group(1))
                        if port not in blocked:
                            blocked.append(port)
                except:
                    continue
    
    if blocked:
        blocked.sort()
        print(f"\nBlocked ports: {blocked}")
    else:
        print("\nNo ports are blocked by firewall.")

def unblock_block_ports():
    risky_ports = [22, 23, 445, 135, 139, 5357, 4899, 5631, 5000, 5009]
    print("\nEnter port to block or unblock:")
    port = input("Port number: ").strip()
    try:
        port = int(port)
    except:
        print("Invalid port number.")
        return
    if platform.system() == "Windows":
        if is_port_actually_blocked(port):
            if unblock_port_windows(port):
                print(f"Port {port} unblocked.")
            else:
                print(f"Failed to unblock port {port}.")
        else:
            if block_port_windows(port):
                print(f"Port {port} blocked.")
            else:
                print(f"Failed to block port {port}.")
    elif platform.system() == "Linux":
        if is_port_actually_blocked(port):
            if unblock_port_linux(port):
                print(f"Port {port} unblocked.")
            else:
                print(f"Failed to unblock port {port}.")
        else:
            if block_port_linux(port):
                print(f"Port {port} blocked.")
            else:
                print(f"Failed to block port {port}.")
    else:
        print("Unsupported OS.")

def main():
    color = set_random_color()
    print("                         d8b                                                                                   d8b ")
    print("                         ?88                                                 d8P         d8P                   88P ")
    print("                          88b                                             d888888P    d888888P                d88  ")
    print(" d888b8b   d8888b d8888b  888  d88' d8888b     ?88,.d88b, d8888b   88bd88b  ?88'        ?88'   d8888b  d8888b 888  ")
    print("d8P' ?88  d8b_,dPd8P' `P  888bd8P' d8P' ?88    `?88'  ?88d8P' ?88  88P'  `  88P         88P   d8P' ?88d8P' ?88?88  ")
    print("88b  ,88b 88b    88b     d88888b   88b  d88      88b  d8P88b  d88 d88       88b         88b   88b  d8888b  d88 88b ")
    print("`?88P'`88b`?888P'`?888P'd88' `?88b,`?8888P'      888888P'`?8888P'd88'       `?8b        `?8b  `?8888P'`?8888P'  88b")
    print("       )88                                       88P'                                                              ")
    print("      ,88P                                      d88                                                                 ")
    print("  `?8888P                                       ?8P                                                                 ")
    print("="*120)
    
    if not check_admin_privileges():
        print("Admin privileges required for port operations.")
        if platform.system() == "Windows":
            try:
                import ctypes
                if ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1) > 32:
                    sys.exit(0)
                else:
                    print("Failed to elevate privileges. Please run as Administrator.")
                    sys.exit(1)
            except:
                print("Failed to elevate privileges. Please run as Administrator.")
                sys.exit(1)
        elif platform.system() == "Linux":
            print("Please run with: sudo python3 GeckoPort.py")
            sys.exit(1)
        else:
            print("Please run with administrator privileges.")
            sys.exit(1)
    
    print("Running with admin privileges.")
    
    while True:
        print("\n1. Scan For ALL Open Ports")
        print("2. Scan Only For RISKY Open Ports")
        print("3. Scan For DANGEROUS Open Ports")
        print("4. Show Blocked Ports (via firewall)")
        print("5. Unblock/Block Ports")
        print("6. Exit")
        choice = input("\nSelect an option: ").strip()
        if choice == "1":
            scan_all_ports()
        elif choice == "2":
            scan_risky_ports()
        elif choice == "3":
            scan_dangerous_ports()
        elif choice == "4":
            show_blocked_ports()
        elif choice == "5":
            unblock_block_ports()
        elif choice == "6":
            print("Exiting.")
            reset_color()
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main() 