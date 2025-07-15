import os
import sys
import subprocess
import platform
import re
import random
import time
import hashlib
import stat
from datetime import datetime, timedelta
from pathlib import Path

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
    """Display the GeckoFiles banner"""
    print("                         d8b                      ,d8888b  d8, d8b                                             d8b ")
    print("                         ?88                      88P'    `8P  88P                       d8P                   88P ")
    print("                          88b                  d888888P       d88                     d888888P                d88  ")
    print(" d888b8b   d8888b d8888b  888  d88' d8888b       ?88'      88b888   d8888b .d888b,      ?88'   d8888b  d8888b 888  ")
    print("d8P' ?88  d8b_,dPd8P' `P  888bd8P' d8P' ?88      88P       88P?88  d8b_,dP ?8b,         88P   d8P' ?88d8P' ?88?88  ")
    print("88b  ,88b 88b    88b     d88888b   88b  d88     d88       d88  88b 88b       `?8b       88b   88b  d8888b  d88 88b ")
    print("`?88P'`88b`?888P'`?888P'd88' `?88b,`?8888P'    d88'      d88'   88b`?888P'`?888P'       `?8b  `?8888P'`?8888P'  88b")
    print("       )88                                                                                                         ")
    print("      ,88P                                                                                                         ")
    print("  `?8888P                                                                                                          ")
    print("======📁 Welcome to Gecko File System Security Assessment Tool")
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

def get_file_hash(file_path):
    """Calculate MD5 hash of a file"""
    try:
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return "Error calculating hash"

def scan_suspicious_files():
    """Scan for suspicious files in common locations"""
    print("🚨 Scanning for Suspicious Files...")
    print()
    
    suspicious_locations = [
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/AppData/Local/Temp"),
        os.path.expanduser("~/AppData/Roaming"),
        os.path.expanduser("~/AppData/Local"),
        os.path.expanduser("~/tmp"),
        "/tmp",
        "/var/tmp"
    ]
    
    # Add Windows-specific paths only on Windows
    if platform.system() == "Windows":
        windows_temp = os.path.join(os.environ.get('TEMP', ''), '') if os.environ.get('TEMP') else "C:/Windows/Temp"
        suspicious_locations.extend([
            windows_temp,
            "C:/Temp"
        ])
    
    suspicious_extensions = [
        '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js',
        '.jar', '.msi', '.dll', '.sys', '.drv', '.ocx', '.cpl', '.hta'
    ]
    
    suspicious_keywords = [
        'keylogger', 'spy', 'monitor', 'track', 'surveillance',
        'crypto', 'miner', 'mining', 'bitcoin', 'ethereum',
        'backdoor', 'trojan', 'malware', 'virus', 'worm',
        'hack', 'crack', 'stealer', 'injector', 'loader'
    ]
    
    suspicious_files = []
    
    for location in suspicious_locations:
        if os.path.exists(location):
            print(f"🔍 Scanning: {location}")
            try:
                for root, dirs, files in os.walk(location):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_lower = file.lower()
                        
                        # Check for suspicious extensions
                        is_suspicious_ext = any(file_lower.endswith(ext) for ext in suspicious_extensions)
                        
                        # Check for suspicious keywords in filename
                        is_suspicious_name = any(keyword in file_lower for keyword in suspicious_keywords)
                        
                        if is_suspicious_ext or is_suspicious_name:
                            try:
                                file_size = os.path.getsize(file_path)
                                file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                                file_hash = get_file_hash(file_path)
                                
                                suspicious_files.append({
                                    'path': file_path,
                                    'name': file,
                                    'size': file_size,
                                    'modified': file_time,
                                    'hash': file_hash,
                                    'reason': 'Suspicious extension' if is_suspicious_ext else 'Suspicious name'
                                })
                            except Exception as e:
                                print(f"⚠️  Error processing file {file}: {str(e)}")
            except Exception as e:
                print(f"⚠️  Error scanning {location}: {str(e)}")
    
    print("\n🚨 Suspicious Files Found:")
    print("="*100)
    
    if not suspicious_files:
        print("✅ No suspicious files found in common locations")
    else:
        print(f"📊 Found {len(suspicious_files)} suspicious files:")
        print()
        
        for i, file_info in enumerate(suspicious_files, 1):
            print(f"{i:2}. 🚨 {file_info['name']}")
            print(f"    Path: {file_info['path']}")
            print(f"    Size: {file_info['size']:,} bytes")
            print(f"    Modified: {file_info['modified'].strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"    Hash: {file_info['hash']}")
            print(f"    Reason: {file_info['reason']}")
            print()
    
    print("="*100)

def scan_recent_files():
    """Scan for recently modified files"""
    print("📅 Scanning Recently Modified Files...")
    print()
    
    # Get current time
    now = datetime.now()
    # Files modified in last 24 hours
    yesterday = now - timedelta(days=1)
    # Files modified in last 7 days
    week_ago = now - timedelta(days=7)
    
    recent_locations = [
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/AppData/Local/Temp"),
        os.path.expanduser("~/tmp"),
        "/tmp",
        "/var/tmp"
    ]
    
    # Add Windows-specific paths only on Windows
    if platform.system() == "Windows":
        windows_temp = os.path.join(os.environ.get('TEMP', ''), '') if os.environ.get('TEMP') else "C:/Windows/Temp"
        recent_locations.append(windows_temp)
    
    recent_files = []
    
    for location in recent_locations:
        if os.path.exists(location):
            print(f"🔍 Scanning: {location}")
            try:
                for root, dirs, files in os.walk(location):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                            
                            # Check if file was modified recently
                            if file_time > yesterday:
                                file_size = os.path.getsize(file_path)
                                recent_files.append({
                                    'path': file_path,
                                    'name': file,
                                    'size': file_size,
                                    'modified': file_time,
                                    'age': 'Last 24 hours'
                                })
                        except Exception:
                            continue
            except Exception as e:
                print(f"⚠️  Error scanning {location}: {str(e)}")
    
    # Sort by modification time (newest first)
    recent_files.sort(key=lambda x: x['modified'], reverse=True)
    
    print("\n📅 Recently Modified Files (Last 24 Hours):")
    print("="*100)
    
    if not recent_files:
        print("✅ No recently modified files found")
    else:
        print(f"📊 Found {len(recent_files)} recently modified files:")
        print()
        
        for i, file_info in enumerate(recent_files[:20], 1):  # Show top 20
            print(f"{i:2}. 📅 {file_info['name']}")
            print(f"    Path: {file_info['path']}")
            print(f"    Size: {file_info['size']:,} bytes")
            print(f"    Modified: {file_info['modified'].strftime('%Y-%m-%d %H:%M:%S')}")
            print()
        
        if len(recent_files) > 20:
            print(f"... and {len(recent_files) - 20} more files")
    
    print("="*100)

def scan_hidden_files():
    """Scan for hidden files and directories"""
    print("👻 Scanning for Hidden Files and Directories...")
    print()
    
    hidden_locations = [
        os.path.expanduser("~"),
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/AppData"),
        "/etc",
        "/var",
        "/usr/local"
    ]
    
    # Add Windows-specific paths only on Windows
    if platform.system() == "Windows":
        hidden_locations.extend([
            "C:/Windows",
            "C:/Program Files",
            "C:/Program Files (x86)"
        ])
    
    hidden_items = []
    
    for location in hidden_locations:
        if os.path.exists(location):
            print(f"🔍 Scanning: {location}")
            try:
                for root, dirs, files in os.walk(location):
                    # Check directories
                    for dir_name in dirs:
                        dir_path = os.path.join(root, dir_name)
                        try:
                            if os.path.isdir(dir_path) and os.path.basename(dir_path).startswith('.'):
                                hidden_items.append({
                                    'path': dir_path,
                                    'name': dir_name,
                                    'type': 'Directory',
                                    'size': 'N/A'
                                })
                        except Exception:
                            continue
                    
                    # Check files
                    for file_name in files:
                        file_path = os.path.join(root, file_name)
                        try:
                            if os.path.basename(file_path).startswith('.'):
                                file_size = os.path.getsize(file_path)
                                hidden_items.append({
                                    'path': file_path,
                                    'name': file_name,
                                    'type': 'File',
                                    'size': file_size
                                })
                        except Exception:
                            continue
            except Exception as e:
                print(f"⚠️  Error scanning {location}: {str(e)}")
    
    print("\n👻 Hidden Files and Directories Found:")
    print("="*100)
    
    if not hidden_items:
        print("✅ No hidden files or directories found")
    else:
        print(f"📊 Found {len(hidden_items)} hidden items:")
        print()
        
        for i, item in enumerate(hidden_items[:30], 1):  # Show top 30
            print(f"{i:2}. 👻 {item['name']}")
            print(f"    Path: {item['path']}")
            print(f"    Type: {item['type']}")
            if item['size'] != 'N/A':
                print(f"    Size: {item['size']:,} bytes")
            print()
        
        if len(hidden_items) > 30:
            print(f"... and {len(hidden_items) - 30} more items")
    
    print("="*100)

def scan_file_permissions():
    """Scan for files with unusual permissions"""
    print("🔐 Scanning File Permissions...")
    print()
    
    permission_locations = [
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/Downloads"),
        "/etc",
        "/usr/local/bin",
        "/usr/bin"
    ]
    
    # Add Windows-specific paths only on Windows
    if platform.system() == "Windows":
        permission_locations.extend([
            "C:/Windows/System32",
            "C:/Program Files"
        ])
    
    unusual_permissions = []
    
    for location in permission_locations:
        if os.path.exists(location):
            print(f"🔍 Scanning: {location}")
            try:
                for root, dirs, files in os.walk(location):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            # Get file permissions
                            file_stat = os.stat(file_path)
                            
                            # Check for executable permissions on non-executable files
                            if platform.system() == "Windows":
                                # On Windows, check if file is executable
                                if file_path.lower().endswith(('.exe', '.bat', '.cmd', '.com')):
                                    continue  # Skip actual executables
                                
                                # Check for unusual attributes
                                if file_stat.st_file_attributes & stat.FILE_ATTRIBUTE_SYSTEM:
                                    unusual_permissions.append({
                                        'path': file_path,
                                        'name': file,
                                        'issue': 'System file attribute',
                                        'permissions': 'System'
                                    })
                            else:
                                # On Unix-like systems, check executable bit
                                if file_stat.st_mode & stat.S_IXUSR:
                                    if not file_path.lower().endswith(('.exe', '.sh', '.py')):
                                        unusual_permissions.append({
                                            'path': file_path,
                                            'name': file,
                                            'issue': 'Executable permission on non-executable file',
                                            'permissions': oct(file_stat.st_mode)[-3:]
                                        })
                        except Exception:
                            continue
            except Exception as e:
                print(f"⚠️  Error scanning {location}: {str(e)}")
    
    print("\n🔐 Files with Unusual Permissions:")
    print("="*100)
    
    if not unusual_permissions:
        print("✅ No files with unusual permissions found")
    else:
        print(f"📊 Found {len(unusual_permissions)} files with unusual permissions:")
        print()
        
        for i, item in enumerate(unusual_permissions, 1):
            print(f"{i:2}. 🔐 {item['name']}")
            print(f"    Path: {item['path']}")
            print(f"    Issue: {item['issue']}")
            print(f"    Permissions: {item['permissions']}")
            print()
    
    print("="*100)

def show_menu():
    """Display the main menu"""
    print("📋 Available Options:")
    print("="*30)
    print("1. 🚨 Scan Suspicious Files")
    print("2. 📅 Scan Recent Files")
    print("3. 👻 Scan Hidden Files")
    print("4. 🔐 Scan File Permissions")
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
                scan_suspicious_files()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '2':
                print()
                scan_recent_files()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '3':
                print()
                scan_hidden_files()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '4':
                print()
                scan_file_permissions()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '5':
                print("👋 Thank you for using GeckoFiles!")
                reset_color()
                break
            
            else:
                print("⚠️  Invalid choice. Please enter 1, 2, 3, 4, or 5.")
                time.sleep(2)
                os.system('cls' if platform.system() == "Windows" else 'clear')
        
        except KeyboardInterrupt:
            print("\n👋 Thank you for using GeckoFiles!")
            reset_color()
            break
        except Exception as e:
            print(f"❌ An error occurred: {str(e)}")
            time.sleep(2)
            os.system('cls' if platform.system() == "Windows" else 'clear')

if __name__ == "__main__":
    main() 