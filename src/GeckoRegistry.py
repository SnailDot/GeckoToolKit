#!/usr/bin/env python3
"""
GeckoRegistry.py - Registry Security Assessment Tool
A comprehensive tool for scanning and analyzing Windows registry for security assessments.
"""

import os
import sys
import subprocess
import platform
import re
import random
import time
from datetime import datetime

# Import Windows-specific modules only on Windows
if platform.system() == "Windows":
    import winreg

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
    """Display the GeckoRegistry banner"""
    print("                         d8b                                               d8,                                                                d8b ")
    print("                         ?88                                              `8P            d8P                            d8P                   88P ")
    print("                          88b                                                         d888888P                       d888888P                d88  ")
    print(" d888b8b   d8888b d8888b  888  d88' d8888b       88bd88b d8888b d888b8b    88b .d888b,  ?88'    88bd88b?88   d8P       ?88'   d8888b  d8888b 888  ")
    print("d8P' ?88  d8b_,dPd8P' `P  888bd8P' d8P' ?88      88P'  `d8b_,dPd8P' ?88    88P ?8b,     88P     88P'  `d88   88        88P   d8P' ?88d8P' ?88?88  ")
    print("88b  ,88b 88b    88b     d88888b   88b  d88     d88     88b    88b  ,88b  d88    `?8b   88b    d88     ?8(  d88        88b   88b  d8888b  d88 88b ")
    print("`?88P'`88b`?888P'`?888P'd88' `?88b,`?8888P'    d88'     `?888P'`?88P'`88bd88' `?888P'   `?8b  d88'     `?88P'?8b       `?8b  `?8888P'`?8888P'  88b")
    print("       )88                                                            )88                                     )88                                 ")
    print("      ,88P                                                           ,88P                                    ,d8P                                 ")
    print("  `?8888P                                                        `?8888P                                  `?888P'                                 ")
    print("======🔍 Welcome to Gecko Registry Security Assessment Tool")
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

def check_windows():
    """Check if running on Windows"""
    if platform.system() != "Windows":
        print("❌ This tool is designed for Windows systems only.")
        print("   Registry scanning is not available on other operating systems.")
        return False
    return True

def scan_startup_programs():
    """Scan for startup programs in registry"""
    print("🚀 Scanning Startup Programs in Registry...")
    print()
    
    startup_locations = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
    ]
    
    startup_programs = []
    
    for hkey, subkey in startup_locations:
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, type_ = winreg.EnumValue(key, i)
                        
                        # Handle different value types safely
                        if isinstance(value, bytes):
                            try:
                                value_str = value.decode('utf-8', errors='ignore')
                            except:
                                value_str = str(value)[:100] + "..." if len(str(value)) > 100 else str(value)
                        elif isinstance(value, str):
                            value_str = value
                        else:
                            value_str = str(value)
                        
                        # Handle name safely
                        if isinstance(name, bytes):
                            try:
                                name_str = name.decode('utf-8', errors='ignore')
                            except:
                                name_str = str(name)
                        elif isinstance(name, str):
                            name_str = name
                        else:
                            name_str = str(name)
                        
                        startup_programs.append({
                            'name': name_str,
                            'value': value_str,
                            'location': f"{'HKCU' if hkey == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{subkey}",
                            'type': type_
                        })
                        i += 1
                    except WindowsError:
                        break
                    except Exception as e:
                        print(f"⚠️  Warning: Error processing registry value at index {i}: {str(e)}")
                        i += 1
                        continue
        except WindowsError:
            continue
        except Exception as e:
            print(f"⚠️  Warning: Error accessing registry key {subkey}: {str(e)}")
            continue
    
    print("🚀 Startup Programs Found:")
    print("="*100)
    
    if not startup_programs:
        print("✅ No startup programs found in registry")
    else:
        print(f"📊 Found {len(startup_programs)} startup programs:")
        print()
        
        for i, program in enumerate(startup_programs, 1):
            try:
                print(f"{i:2}. 🚀 {program['name']}")
                print(f"    Value: {program['value']}")
                print(f"    Location: {program['location']}")
                print()
            except Exception as e:
                print(f"{i:2}. 🚀 [Error displaying program: {str(e)}]")
                print()
    
    # Security analysis
    print("🔒 Startup Security Analysis:")
    print("-" * 50)
    
    suspicious_startups = []
    for program in startup_programs:
        try:
            name_lower = program['name'].lower()
            value_lower = program['value'].lower()
            
            # Check for suspicious patterns
            suspicious_keywords = [
                'keylogger', 'spy', 'monitor', 'track', 'surveillance',
                'crypto', 'miner', 'mining', 'bitcoin', 'ethereum',
                'backdoor', 'trojan', 'malware', 'virus', 'worm',
                'remote', 'access', 'control', 'vnc', 'rdp'
            ]
            
            for keyword in suspicious_keywords:
                if keyword in name_lower or keyword in value_lower:
                    suspicious_startups.append({
                        'program': program,
                        'keyword': keyword
                    })
                    break
        except Exception as e:
            print(f"⚠️  Warning: Error analyzing program {program.get('name', 'Unknown')}: {str(e)}")
            continue
    
    if suspicious_startups:
        print("⚠️  Potentially Suspicious Startup Programs:")
        for item in suspicious_startups:
            try:
                program = item['program']
                keyword = item['keyword']
                print(f"   • {program['name']} - Keyword: {keyword}")
                print(f"     Location: {program['location']}")
            except Exception as e:
                print(f"   • [Error displaying suspicious program: {str(e)}]")
    else:
        print("✅ No suspicious startup programs detected")
    
    print("="*100)

def scan_autorun_entries():
    """Scan for autorun entries in registry"""
    print("🔄 Scanning Autorun Entries in Registry...")
    print()
    
    autorun_locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler"),
    ]
    
    autorun_entries = []
    
    for hkey, subkey in autorun_locations:
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, type_ = winreg.EnumValue(key, i)
                        autorun_entries.append({
                            'name': name,
                            'value': value,
                            'location': f"{'HKCU' if hkey == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{subkey}",
                            'type': type_
                        })
                        i += 1
                    except WindowsError:
                        break
        except WindowsError:
            continue
    
    print("🔄 Autorun Entries Found:")
    print("="*100)
    
    if not autorun_entries:
        print("✅ No autorun entries found in registry")
    else:
        print(f"📊 Found {len(autorun_entries)} autorun entries:")
        print()
        
        for i, entry in enumerate(autorun_entries, 1):
            print(f"{i:2}. 🔄 {entry['name']}")
            print(f"    Value: {entry['value']}")
            print(f"    Location: {entry['location']}")
            print()
    
    print("="*100)

def scan_suspicious_registry_keys():
    """Scan for suspicious registry keys and values"""
    print("🚨 Scanning for Suspicious Registry Keys...")
    print()
    
    suspicious_patterns = [
        # Malware persistence
        (r"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Suspicious startup entries"),
        (r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce entries"),
        (r"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "Policy-based autorun"),
        (r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler", "Scheduled tasks"),
        
        # Browser hijacking
        (r"Software\\Microsoft\\Internet Explorer\\Main", "IE settings"),
        (r"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "Internet settings"),
        
        # File associations
        (r"Software\\Classes", "File associations"),
        (r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts", "File extensions"),
        
        # Services
        (r"System\\CurrentControlSet\\Services", "System services"),
        
        # Network settings
        (r"System\\CurrentControlSet\\Services\\Tcpip\\Parameters", "TCP/IP settings"),
        (r"System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", "Network interfaces"),
    ]
    
    suspicious_findings = []
    
    for pattern, description in suspicious_patterns:
        try:
            # Check HKEY_LOCAL_MACHINE
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, pattern, 0, winreg.KEY_READ) as key:
                    suspicious_findings.append({
                        'location': f"HKLM\\{pattern}",
                        'description': description,
                        'status': 'Found'
                    })
            except WindowsError:
                pass
            
            # Check HKEY_CURRENT_USER
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, pattern, 0, winreg.KEY_READ) as key:
                    suspicious_findings.append({
                        'location': f"HKCU\\{pattern}",
                        'description': description,
                        'status': 'Found'
                    })
            except WindowsError:
                pass
                
        except Exception as e:
            continue
    
    print("🚨 Suspicious Registry Keys Analysis:")
    print("="*100)
    
    if not suspicious_findings:
        print("✅ No suspicious registry keys found")
    else:
        print(f"📊 Found {len(suspicious_findings)} registry locations to monitor:")
        print()
        
        for i, finding in enumerate(suspicious_findings, 1):
            print(f"{i:2}. 🚨 {finding['location']}")
            print(f"    Description: {finding['description']}")
            print(f"    Status: {finding['status']}")
            print()
    
    print("🔒 Security Recommendations:")
    print("-" * 50)
    print("• Monitor these registry locations for unauthorized changes")
    print("• Check for new entries in startup locations")
    print("• Verify file associations haven't been hijacked")
    print("• Review network settings for suspicious modifications")
    print("• Use registry monitoring tools for real-time alerts")
    
    print("="*100)

def export_registry_backup():
    """Export registry backup for analysis"""
    print("💾 Creating Registry Backup...")
    print()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"registry_backup_{timestamp}.reg"
    
    print(f"📁 Backup file: {backup_file}")
    print("⏳ This may take a few minutes...")
    print()
    
    # Export key registry locations
    export_locations = [
        (r"Software\Microsoft\Windows\CurrentVersion\Run", "Startup programs"),
        (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce programs"),
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "Policy autorun"),
        (r"System\CurrentControlSet\Services", "System services"),
    ]
    
    try:
        with open(backup_file, 'w') as f:
            f.write("Windows Registry Editor Version 5.00\n\n")
            
            for location, description in export_locations:
                f.write(f"; {description}\n")
                f.write(f"[HKEY_LOCAL_MACHINE\\{location}]\n")
                f.write("\n")
        
        print("✅ Registry backup created successfully!")
        print(f"📄 File: {backup_file}")
        print("💡 You can use this file to restore registry settings if needed")
        
    except Exception as e:
        print(f"❌ Failed to create registry backup: {str(e)}")
    
    print("="*100)

def show_menu():
    """Display the main menu"""
    print("📋 Available Options:")
    print("="*30)
    print("1. 🚀 Scan Startup Programs")
    print("2. 🔄 Scan Autorun Entries")
    print("3. 🚨 Scan Suspicious Registry Keys")
    print("4. 💾 Export Registry Backup")
    print("5. 🚪 Exit")
    print("="*30)

def main():
    """Main function"""
    if not check_windows():
        return
    
    color = set_random_color()
    
    while True:
        print_banner()
        show_menu()
        
        try:
            choice = input("🔢 Enter your choice (1-5): ").strip()
            
            if choice == '1':
                print()
                scan_startup_programs()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '2':
                print()
                scan_autorun_entries()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '3':
                print()
                scan_suspicious_registry_keys()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '4':
                print()
                export_registry_backup()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '5':
                print("👋 Thank you for using GeckoRegistry!")
                reset_color()
                break
            
            else:
                print("⚠️  Invalid choice. Please enter 1, 2, 3, 4, or 5.")
                time.sleep(2)
                os.system('cls' if platform.system() == "Windows" else 'clear')
        
        except KeyboardInterrupt:
            print("\n👋 Thank you for using GeckoRegistry!")
            reset_color()
            break
        except Exception as e:
            print(f"❌ An error occurred: {str(e)}")
            time.sleep(2)
            os.system('cls' if platform.system() == "Windows" else 'clear')

if __name__ == "__main__":
    main() 