#!/usr/bin/env python3
"""
GeckoProcess.py - Process Security Assessment Tool
A comprehensive tool for monitoring running processes and detecting unauthorized ones for laptop security assessments.
"""

import os
import sys
import subprocess
import platform
import re
import random
import time
import psutil
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
    """Display the GeckoProcess banner"""
    print("                         d8b                                                                                                                        d8b ")
    print("                         ?88                                                                                                  d8P                   88P ")
    print("                          88b                                                                                              d888888P                d88  ")
    print(" d888b8b   d8888b d8888b  888  d88' d8888b     ?88,.d88b,  88bd88b d8888b  d8888b d8888b .d888b, .d888b, d8888b .d888b,      ?88'   d8888b  d8888b 888  ")
    print("d8P' ?88  d8b_,dPd8P' `P  888bd8P' d8P' ?88    `?88'  ?88  88P'  `d8P' ?88d8P' `Pd8b_,dP ?8b,    ?8b,   d8b_,dP ?8b,         88P   d8P' ?88d8P' ?88?88  ")
    print("88b  ,88b 88b    88b     d88888b   88b  d88      88b  d8P d88     88b  d8888b    88b       `?8b    `?8b 88b       `?8b       88b   88b  d8888b  d88 88b ")
    print("`?88P'`88b`?888P'`?888P'd88' `?88b,`?8888P'      888888P'd88'     `?8888P'`?888P'`?888P'`?888P' `?888P' `?888P'`?888P'       `?8b  `?8888P'`?8888P'  88b")
    print("       )88                                       88P'                                                                                                   ")
    print("      ,88P                                      d88                                                                                                     ")
    print("  `?8888P                                       ?8P                                                                                                     ")
    print("======🔄 Welcome to Gecko Process Security Assessment Tool")
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

def get_process_info_windows():
    """Get detailed process information on Windows"""
    processes = []
    
    try:
        # Get process list with detailed information
        success, stdout, stderr = run_command('tasklist /fo csv /v')
        if success:
            lines = stdout.strip().split('\n')
            if len(lines) > 1:  # Skip header
                for line in lines[1:]:
                    if line.strip():
                        # Parse CSV format
                        parts = line.split('","')
                        if len(parts) >= 8:
                            process_info = {
                                'name': parts[0].strip('"'),
                                'pid': parts[1].strip('"'),
                                'session': parts[2].strip('"'),
                                'memory': parts[4].strip('"'),
                                'status': parts[5].strip('"'),
                                'username': parts[6].strip('"'),
                                'cpu_time': parts[7].strip('"'),
                                'window_title': parts[8].strip('"') if len(parts) > 8 else ''
                            }
                            processes.append(process_info)
    except Exception as e:
        print(f"Error getting process info: {str(e)}")
    
    return processes

def get_process_info_linux():
    """Get detailed process information on Linux"""
    processes = []
    
    try:
        # Get process list with detailed information
        success, stdout, stderr = run_command('ps aux')
        if success:
            lines = stdout.strip().split('\n')
            if len(lines) > 1:  # Skip header
                for line in lines[1:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 11:
                            process_info = {
                                'username': parts[0],
                                'pid': parts[1],
                                'cpu': parts[2],
                                'memory': parts[3],
                                'vsz': parts[4],
                                'rss': parts[5],
                                'tty': parts[6],
                                'status': parts[7],
                                'start': parts[8],
                                'time': parts[9],
                                'command': ' '.join(parts[10:])
                            }
                            processes.append(process_info)
    except Exception as e:
        print(f"Error getting process info: {str(e)}")
    
    return processes

def get_process_info_macos():
    """Get detailed process information on macOS"""
    processes = []
    
    try:
        # Get process list with detailed information
        success, stdout, stderr = run_command('ps aux')
        if success:
            lines = stdout.strip().split('\n')
            if len(lines) > 1:  # Skip header
                for line in lines[1:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 11:
                            process_info = {
                                'username': parts[0],
                                'pid': parts[1],
                                'cpu': parts[2],
                                'memory': parts[3],
                                'vsz': parts[4],
                                'rss': parts[5],
                                'tty': parts[6],
                                'status': parts[7],
                                'start': parts[8],
                                'time': parts[9],
                                'command': ' '.join(parts[10:])
                            }
                            processes.append(process_info)
    except Exception as e:
        print(f"Error getting process info: {str(e)}")
    
    return processes

def get_process_tree_windows():
    """Get process tree information on Windows"""
    process_trees = {}
    
    try:
        # Get process list with parent-child relationships
        success, stdout, stderr = run_command('wmic process get ProcessId,ParentProcessId,Name /format:csv')
        if success:
            lines = stdout.strip().split('\n')
            if len(lines) > 1:  # Skip header
                for line in lines[1:]:
                    if line.strip() and ',' in line:
                        parts = line.split(',')
                        if len(parts) >= 3:
                            try:
                                pid = parts[1].strip()
                                ppid = parts[2].strip()
                                name = parts[3].strip()
                                
                                if pid and ppid and name:
                                    if ppid not in process_trees:
                                        process_trees[ppid] = []
                                    process_trees[ppid].append({
                                        'pid': pid,
                                        'name': name
                                    })
                            except (ValueError, IndexError):
                                continue
    except Exception as e:
        print(f"Error getting process tree: {str(e)}")
    
    return process_trees

def get_process_tree_linux():
    """Get process tree information on Linux"""
    process_trees = {}
    
    try:
        # Get process list with parent-child relationships
        success, stdout, stderr = run_command('ps -eo pid,ppid,comm --no-headers')
        if success:
            lines = stdout.strip().split('\n')
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            pid = parts[0].strip()
                            ppid = parts[1].strip()
                            name = parts[2].strip()
                            
                            if pid and ppid and name:
                                if ppid not in process_trees:
                                    process_trees[ppid] = []
                                process_trees[ppid].append({
                                    'pid': pid,
                                    'name': name
                                })
                        except (ValueError, IndexError):
                            continue
    except Exception as e:
        print(f"Error getting process tree: {str(e)}")
    
    return process_trees

def get_process_tree_macos():
    """Get process tree information on macOS"""
    process_trees = {}
    
    try:
        # Get process list with parent-child relationships
        success, stdout, stderr = run_command('ps -eo pid,ppid,comm --no-headers')
        if success:
            lines = stdout.strip().split('\n')
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            pid = parts[0].strip()
                            ppid = parts[1].strip()
                            name = parts[2].strip()
                            
                            if pid and ppid and name:
                                if ppid not in process_trees:
                                    process_trees[ppid] = []
                                process_trees[ppid].append({
                                    'pid': pid,
                                    'name': name
                                })
                        except (ValueError, IndexError):
                            continue
    except Exception as e:
        print(f"Error getting process tree: {str(e)}")
    
    return process_trees

def list_all_processes():
    """List all currently running processes"""
    print("🔄 Listing All Currently Running Processes...")
    print()
    
    if platform.system() == "Windows":
        processes = get_process_info_windows()
        print("🔄 Current Windows Processes:")
        print("="*100)
        print(f"{'PID':<8} {'Name':<25} {'Memory':<12} {'Status':<10} {'Username':<15} {'CPU Time':<12}")
        print("-" * 100)
        
        for process in processes[:50]:  # Show first 50 processes
            pid = process.get('pid', 'N/A')
            name = process.get('name', 'Unknown')[:24]
            memory = process.get('memory', 'N/A')
            status = process.get('status', 'Unknown')[:9]
            username = process.get('username', 'Unknown')[:14]
            cpu_time = process.get('cpu_time', 'N/A')[:11]
            
            print(f"{pid:<8} {name:<25} {memory:<12} {status:<10} {username:<15} {cpu_time:<12}")
        
        if len(processes) > 50:
            print(f"\n... and {len(processes) - 50} more processes")
        
        print(f"\n📊 Total Processes: {len(processes)}")
        
    elif platform.system() == "Linux":
        processes = get_process_info_linux()
        print("🔄 Current Linux Processes:")
        print("="*100)
        print(f"{'PID':<8} {'User':<12} {'CPU%':<6} {'MEM%':<6} {'Command':<50}")
        print("-" * 100)
        
        for process in processes[:50]:  # Show first 50 processes
            pid = process.get('pid', 'N/A')
            username = process.get('username', 'Unknown')[:11]
            cpu = process.get('cpu', 'N/A')[:5]
            memory = process.get('memory', 'N/A')[:5]
            command = process.get('command', 'Unknown')[:49]
            
            print(f"{pid:<8} {username:<12} {cpu:<6} {memory:<6} {command:<50}")
        
        if len(processes) > 50:
            print(f"\n... and {len(processes) - 50} more processes")
        
        print(f"\n📊 Total Processes: {len(processes)}")
        
    elif platform.system() == "Darwin":  # macOS
        processes = get_process_info_macos()
        print("🔄 Current macOS Processes:")
        print("="*100)
        print(f"{'PID':<8} {'User':<12} {'CPU%':<6} {'MEM%':<6} {'Command':<50}")
        print("-" * 100)
        
        for process in processes[:50]:  # Show first 50 processes
            pid = process.get('pid', 'N/A')
            username = process.get('username', 'Unknown')[:11]
            cpu = process.get('cpu', 'N/A')[:5]
            memory = process.get('memory', 'N/A')[:5]
            command = process.get('command', 'Unknown')[:49]
            
            print(f"{pid:<8} {username:<12} {cpu:<6} {memory:<6} {command:<50}")
        
        if len(processes) > 50:
            print(f"\n... and {len(processes) - 50} more processes")
        
        print(f"\n📊 Total Processes: {len(processes)}")
    
    else:
        print("❌ Unsupported operating system")
    
    print("="*100)

def get_suspicious_processes():
    """Get list of potentially suspicious processes"""
    suspicious_keywords = [
        # Remote access tools
        'teamviewer', 'anydesk', 'vnc', 'rdp', 'remote', 'ssh', 'telnet',
        # Network tools
        'wireshark', 'fiddler', 'burp', 'nmap', 'netcat', 'nc', 'tcpdump',
        # File sharing
        'utorrent', 'bittorrent', 'transmission', 'deluge', 'qbittorrent',
        # Monitoring tools
        'keylogger', 'spy', 'monitor', 'track', 'surveillance',
        # Malware indicators
        'crypto', 'miner', 'mining', 'bitcoin', 'ethereum', 'wallet',
        # Unusual names
        'svchost', 'lsass', 'csrss', 'winlogon', 'explorer', 'chrome',
        # Suspicious patterns
        'update', 'service', 'helper', 'assistant', 'manager', 'tool',
        # Encrypted communication
        'tor', 'vpn', 'proxy', 'tunnel', 'bridge',
        # Development tools (potential backdoors)
        'python', 'node', 'java', 'php', 'ruby', 'perl'
    ]
    
    return suspicious_keywords

def list_unauthorized_processes():
    """List potentially unauthorized or suspicious processes"""
    print("🚨 Scanning for Unauthorized/Suspicious Processes...")
    print()
    
    if platform.system() == "Windows":
        processes = get_process_info_windows()
    elif platform.system() == "Linux":
        processes = get_process_info_linux()
    elif platform.system() == "Darwin":  # macOS
        processes = get_process_info_macos()
    else:
        print("❌ Unsupported operating system")
        return
    
    suspicious_keywords = get_suspicious_processes()
    suspicious_processes = []
    
    print("🚨 Potentially Suspicious Processes:")
    print("="*100)
    
    for process in processes:
        process_name = process.get('name', '').lower()
        if platform.system() != "Windows":
            command = process.get('command', '').lower()
        else:
            command = process_name
        
        # Check for suspicious keywords
        for keyword in suspicious_keywords:
            if keyword in process_name or keyword in command:
                suspicious_processes.append({
                    'process': process,
                    'keyword': keyword,
                    'risk_level': 'HIGH' if keyword in ['keylogger', 'spy', 'miner', 'crypto'] else 'MEDIUM'
                })
                break
    
    if not suspicious_processes:
        print("✅ No suspicious processes detected!")
        print("   All running processes appear to be legitimate system processes.")
    else:
        print(f"⚠️  Found {len(suspicious_processes)} potentially suspicious processes:")
        print()
        
        for i, item in enumerate(suspicious_processes, 1):
            process = item['process']
            keyword = item['keyword']
            risk_level = item['risk_level']
            
            if platform.system() == "Windows":
                pid = process.get('pid', 'N/A')
                name = process.get('name', 'Unknown')
                memory = process.get('memory', 'N/A')
                username = process.get('username', 'Unknown')
                cpu_time = process.get('cpu_time', 'N/A')
                
                print(f"{i:2}. 🚨 {name} (PID: {pid})")
                print(f"    Risk Level: {risk_level} | Keyword: {keyword}")
                print(f"    Memory: {memory} | CPU Time: {cpu_time}")
                print(f"    User: {username}")
                print()
            else:
                pid = process.get('pid', 'N/A')
                username = process.get('username', 'Unknown')
                cpu = process.get('cpu', 'N/A')
                memory = process.get('memory', 'N/A')
                command = process.get('command', 'Unknown')
                
                print(f"{i:2}. 🚨 {command} (PID: {pid})")
                print(f"    Risk Level: {risk_level} | Keyword: {keyword}")
                print(f"    CPU: {cpu}% | Memory: {memory}%")
                print(f"    User: {username}")
                print()
    
    # Additional security recommendations
    print("🔒 Security Recommendations:")
    print("-" * 50)
    print("• Investigate any HIGH risk processes immediately")
    print("• Check MEDIUM risk processes for legitimacy")
    print("• Monitor process behavior and network activity")
    print("• Consider terminating suspicious processes")
    print("• Update antivirus and run full system scan")
    print("• Check for unauthorized startup programs")
    print("• Review recent file modifications")
    
    print("="*100)

def list_process_trees():
    """List processes with their child processes"""
    print("🌳 Scanning Process Trees...")
    print()
    
    if platform.system() == "Windows":
        process_trees = get_process_tree_windows()
    elif platform.system() == "Linux":
        process_trees = get_process_tree_linux()
    elif platform.system() == "Darwin":  # macOS
        process_trees = get_process_tree_macos()
    else:
        print("❌ Unsupported operating system")
        return
    
    # Get parent process names
    parent_names = {}
    if platform.system() == "Windows":
        success, stdout, stderr = run_command('tasklist /fo csv /v')
        if success:
            lines = stdout.strip().split('\n')
            if len(lines) > 1:
                for line in lines[1:]:
                    if line.strip():
                        parts = line.split('","')
                        if len(parts) >= 2:
                            pid = parts[1].strip('"')
                            name = parts[0].strip('"')
                            parent_names[pid] = name
    else:
        success, stdout, stderr = run_command('ps -eo pid,comm --no-headers')
        if success:
            lines = stdout.strip().split('\n')
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        pid = parts[0].strip()
                        name = parts[1].strip()
                        parent_names[pid] = name
    
    print("🌳 Processes with Child Processes:")
    print("="*100)
    
    if not process_trees:
        print("ℹ️  No process trees found or unable to retrieve process hierarchy.")
        return
    
    tree_count = 0
    for ppid, children in process_trees.items():
        if children:  # Only show processes that have children
            tree_count += 1
            parent_name = parent_names.get(ppid, f"Unknown (PID: {ppid})")
            
            print(f"🌳 Parent Process: {parent_name} (PID: {ppid})")
            print(f"   📋 Child Processes ({len(children)}):")
            
            for i, child in enumerate(children, 1):
                child_pid = child['pid']
                child_name = child['name']
                print(f"      {i}. {child_name} (PID: {child_pid})")
            
            print("-" * 100)
    
    print(f"📊 Total Process Trees Found: {tree_count}")
    
    # Security analysis
    print("\n🔒 Process Tree Security Analysis:")
    print("-" * 50)
    
    suspicious_parents = []
    for ppid, children in process_trees.items():
        if children:
            parent_name = parent_names.get(ppid, "").lower()
            
            # Check for suspicious parent processes
            suspicious_keywords = ['explorer', 'svchost', 'lsass', 'csrss', 'winlogon']
            for keyword in suspicious_keywords:
                if keyword in parent_name:
                    suspicious_parents.append({
                        'pid': ppid,
                        'name': parent_names.get(ppid, "Unknown"),
                        'children_count': len(children),
                        'keyword': keyword
                    })
                    break
    
    if suspicious_parents:
        print("⚠️  Potentially Suspicious Parent Processes:")
        for item in suspicious_parents:
            print(f"   • {item['name']} (PID: {item['pid']}) - {item['children_count']} children")
            print(f"     Keyword: {item['keyword']}")
    else:
        print("✅ No suspicious parent processes detected")
    
    print("\n💡 Security Tips:")
    print("• Monitor processes with many children")
    print("• Check for unusual parent-child relationships")
    print("• Investigate processes spawning unexpected children")
    print("• Look for privilege escalation patterns")
    
    print("="*100)

def kill_process():
    """Kill a process by name or PID"""
    print("💀 Kill Process")
    print("="*50)
    print("Enter either:")
    print("• Process name (e.g., 'chrome.exe')")
    print("• Process ID (e.g., '1234')")
    print()
    
    target = input("🎯 Enter process name or PID: ").strip()
    
    if not target:
        print("❌ No process specified")
        return
    
    # Check if input is a PID (numeric)
    is_pid = target.isdigit()
    
    if platform.system() == "Windows":
        if is_pid:
            # Kill by PID
            success, stdout, stderr = run_command(f'taskkill /PID {target} /F')
            if success:
                print(f"✅ Successfully killed process with PID: {target}")
            else:
                print(f"❌ Failed to kill process with PID: {target}")
                if stderr:
                    print(f"Error: {stderr}")
        else:
            # Kill by name
            success, stdout, stderr = run_command(f'taskkill /IM "{target}" /F')
            if success:
                print(f"✅ Successfully killed process(es): {target}")
            else:
                print(f"❌ Failed to kill process: {target}")
                if stderr:
                    print(f"Error: {stderr}")
    
    elif platform.system() == "Linux":
        if is_pid:
            # Kill by PID
            success, stdout, stderr = run_command(f'kill -9 {target}')
            if success:
                print(f"✅ Successfully killed process with PID: {target}")
            else:
                print(f"❌ Failed to kill process with PID: {target}")
                if stderr:
                    print(f"Error: {stderr}")
        else:
            # Kill by name
            success, stdout, stderr = run_command(f'pkill -f "{target}"')
            if success:
                print(f"✅ Successfully killed process(es): {target}")
            else:
                print(f"❌ Failed to kill process: {target}")
                if stderr:
                    print(f"Error: {stderr}")
    
    elif platform.system() == "Darwin":  # macOS
        if is_pid:
            # Kill by PID
            success, stdout, stderr = run_command(f'kill -9 {target}')
            if success:
                print(f"✅ Successfully killed process with PID: {target}")
            else:
                print(f"❌ Failed to kill process with PID: {target}")
                if stderr:
                    print(f"Error: {stderr}")
        else:
            # Kill by name
            success, stdout, stderr = run_command(f'pkill -f "{target}"')
            if success:
                print(f"✅ Successfully killed process(es): {target}")
            else:
                print(f"❌ Failed to kill process: {target}")
                if stderr:
                    print(f"Error: {stderr}")
    
    else:
        print("❌ Unsupported operating system")
    
    print("="*50)

def get_process_path_by_pid(pid):
    """Get the full path of a process by PID"""
    if platform.system() == "Windows":
        success, stdout, stderr = run_command(f'wmic process where ProcessId={pid} get ExecutablePath /format:csv')
        if success and stdout.strip():
            lines = stdout.strip().split('\n')
            if len(lines) > 1:
                parts = lines[1].split(',')
                if len(parts) >= 2:
                    return parts[1].strip().strip('"')
    elif platform.system() in ["Linux", "Darwin"]:
        success, stdout, stderr = run_command(f'ps -p {pid} -o comm=')
        if success and stdout.strip():
            return stdout.strip()
    return None

def get_process_path_by_name(name):
    """Get the full path of a process by name"""
    if platform.system() == "Windows":
        success, stdout, stderr = run_command(f'wmic process where Name="{name}" get ExecutablePath /format:csv')
        if success and stdout.strip():
            lines = stdout.strip().split('\n')
            if len(lines) > 1:
                parts = lines[1].split(',')
                if len(parts) >= 2:
                    return parts[1].strip().strip('"')
    elif platform.system() in ["Linux", "Darwin"]:
        success, stdout, stderr = run_command(f'which {name}')
        if success and stdout.strip():
            return stdout.strip()
    return None

def check_firewall_rule_exists(process_path):
    """Check if a firewall rule exists for the process"""
    if platform.system() == "Windows":
        # Check for existing firewall rule
        rule_name = f"Block_{os.path.basename(process_path)}"
        success, stdout, stderr = run_command(f'netsh advfirewall firewall show rule name="{rule_name}"')
        return "No rules match the specified criteria" not in stdout
    elif platform.system() == "Linux":
        # Check iptables for existing rule
        success, stdout, stderr = run_command(f'iptables -L -n | grep "{process_path}"')
        return success and stdout.strip()
    elif platform.system() == "Darwin":
        # Check pfctl for existing rule
        success, stdout, stderr = run_command(f'pfctl -sr | grep "{process_path}"')
        return success and stdout.strip()
    return False

def block_process_via_firewall():
    """Block or unblock a process via firewall"""
    print("🔥 Block/Unblock Process via Firewall")
    print("="*60)
    print("This will:")
    print("• Create a firewall rule to block the process")
    print("• Kill the process after blocking")
    print("• Remove existing firewall rule if already blocked")
    print()
    print("Enter either:")
    print("• Process name (e.g., 'chrome.exe')")
    print("• Process ID (e.g., '1234')")
    print()
    
    target = input("🎯 Enter process name or PID: ").strip()
    
    if not target:
        print("❌ No process specified")
        return
    
    # Check if input is a PID (numeric)
    is_pid = target.isdigit()
    
    # Get process path
    if is_pid:
        process_path = get_process_path_by_pid(target)
        if not process_path:
            print(f"❌ Could not find process with PID: {target}")
            return
    else:
        process_path = get_process_path_by_name(target)
        if not process_path:
            print(f"❌ Could not find process: {target}")
            return
    
    print(f"📍 Process path: {process_path}")
    
    # Check if firewall rule already exists
    rule_exists = check_firewall_rule_exists(process_path)
    
    if platform.system() == "Windows":
        rule_name = f"Block_{os.path.basename(process_path)}"
        
        if rule_exists:
            print(f"🔄 Removing existing firewall rule: {rule_name}")
            success, stdout, stderr = run_command(f'netsh advfirewall firewall delete rule name="{rule_name}"')
            if success:
                print(f"✅ Successfully removed firewall rule: {rule_name}")
            else:
                print(f"❌ Failed to remove firewall rule: {rule_name}")
                if stderr:
                    print(f"Error: {stderr}")
        else:
            print(f"🛡️  Creating firewall rule to block: {os.path.basename(process_path)}")
            success, stdout, stderr = run_command(
                f'netsh advfirewall firewall add rule name="{rule_name}" '
                f'dir=out program="{process_path}" action=block'
            )
            if success:
                print(f"✅ Successfully created firewall rule: {rule_name}")
                
                # Kill the process after blocking
                if is_pid:
                    kill_success, _, _ = run_command(f'taskkill /PID {target} /F')
                else:
                    kill_success, _, _ = run_command(f'taskkill /IM "{target}" /F')
                
                if kill_success:
                    print(f"💀 Successfully killed process: {target}")
                else:
                    print(f"⚠️  Process blocked but could not kill: {target}")
            else:
                print(f"❌ Failed to create firewall rule: {rule_name}")
                if stderr:
                    print(f"Error: {stderr}")
    
    elif platform.system() == "Linux":
        if rule_exists:
            print("🔄 Removing existing firewall rule")
            success, stdout, stderr = run_command(f'iptables -D OUTPUT -m owner --pid-owner $(pgrep -f "{process_path}") -j DROP')
            if success:
                print("✅ Successfully removed firewall rule")
            else:
                print("❌ Failed to remove firewall rule")
                if stderr:
                    print(f"Error: {stderr}")
        else:
            print(f"🛡️  Creating firewall rule to block: {os.path.basename(process_path)}")
            success, stdout, stderr = run_command(f'iptables -A OUTPUT -m owner --pid-owner $(pgrep -f "{process_path}") -j DROP')
            if success:
                print("✅ Successfully created firewall rule")
                
                # Kill the process after blocking
                if is_pid:
                    kill_success, _, _ = run_command(f'kill -9 {target}')
                else:
                    kill_success, _, _ = run_command(f'pkill -f "{target}"')
                
                if kill_success:
                    print(f"💀 Successfully killed process: {target}")
                else:
                    print(f"⚠️  Process blocked but could not kill: {target}")
            else:
                print("❌ Failed to create firewall rule")
                if stderr:
                    print(f"Error: {stderr}")
    
    elif platform.system() == "Darwin":  # macOS
        if rule_exists:
            print("🔄 Removing existing firewall rule")
            success, stdout, stderr = run_command(f'pfctl -sr | grep -v "{process_path}" | pfctl -f -')
            if success:
                print("✅ Successfully removed firewall rule")
            else:
                print("❌ Failed to remove firewall rule")
                if stderr:
                    print(f"Error: {stderr}")
        else:
            print(f"🛡️  Creating firewall rule to block: {os.path.basename(process_path)}")
            # Add rule to pf.conf
            rule_content = f'block out proto tcp from any to any owner {process_path}\n'
            success, stdout, stderr = run_command(f'echo "{rule_content}" >> /etc/pf.conf && pfctl -f /etc/pf.conf')
            if success:
                print("✅ Successfully created firewall rule")
                
                # Kill the process after blocking
                if is_pid:
                    kill_success, _, _ = run_command(f'kill -9 {target}')
                else:
                    kill_success, _, _ = run_command(f'pkill -f "{target}"')
                
                if kill_success:
                    print(f"💀 Successfully killed process: {target}")
                else:
                    print(f"⚠️  Process blocked but could not kill: {target}")
            else:
                print("❌ Failed to create firewall rule")
                if stderr:
                    print(f"Error: {stderr}")
    
    else:
        print("❌ Unsupported operating system")
    
    print("="*60)

def show_menu():
    """Display the main menu"""
    print("📋 Available Options:")
    print("="*30)
    print("1. 🔄 List All Processes Currently Running")
    print("2. 🚨 List Unauthorized Processes")
    print("3. 🌳 Check Process Trees")
    print("4. 💀 Kill Process")
    print("5. 🔥 Block/Unblock Process via Firewall")
    print("6. 🚪 Exit")
    print("="*30)

def main():
    """Main function"""
    color = set_random_color()
    
    while True:
        print_banner()
        show_menu()
        
        try:
            choice = input("🔢 Enter your choice (1-6): ").strip()
            
            if choice == '1':
                print()
                list_all_processes()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '2':
                print()
                list_unauthorized_processes()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '3':
                print()
                list_process_trees()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '4':
                print()
                kill_process()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '5':
                print()
                block_process_via_firewall()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '6':
                print("👋 Thank you for using GeckoProcess!")
                reset_color()
                break
            
            else:
                print("⚠️  Invalid choice. Please enter 1, 2, 3, 4, 5, or 6.")
                time.sleep(2)
                os.system('cls' if platform.system() == "Windows" else 'clear')
        
        except KeyboardInterrupt:
            print("\n👋 Thank you for using GeckoProcess!")
            reset_color()
            break
        except Exception as e:
            print(f"❌ An error occurred: {str(e)}")
            time.sleep(2)
            os.system('cls' if platform.system() == "Windows" else 'clear')

if __name__ == "__main__":
    main() 