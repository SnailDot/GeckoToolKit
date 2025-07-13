#!/usr/bin/env python3
"""
GeckoTools.py - Gecko Toolkit Launcher
A unified launcher for all Gecko tools including IP scanning, port management, and device information.
"""

import os
import sys
import subprocess
import platform
import random
import time

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
    """Display the GeckoTools banner"""
    print("                         d8b                                            d8b      d8b         d8,        ")
    print("                         ?88                      d8P                   88P      ?88        `8P    d8P  ")
    print("                          88b                  d888888P                d88        88b           d888888P")
    print(" d888b8b   d8888b d8888b  888  d88' d8888b       ?88'   d8888b  d8888b 888        888  d88'  88b  ?88'  ")
    print("d8P' ?88  d8b_,dPd8P' `P  888bd8P' d8P' ?88      88P   d8P' ?88d8P' ?88?88        888bd8P'   88P  88P   ")
    print("88b  ,88b 88b    88b     d88888b   88b  d88      88b   88b  d8888b  d88 88b      d88888b    d88   88b   ")
    print("`?88P'`88b`?888P'`?888P'd88' `?88b,`?8888P'      `?8b  `?8888P'`?8888P'  88b    d88' `?88b,d88'   `?8b  ")
    print("       )88                                                                                              ")
    print("      ,88P                                                                                              ")
    print("  `?8888P                                                                                               ")
    print("="*120)
    print("🔧 Welcome to Gecko Toolkit Launcher!")
    print("💡 Choose a tool to launch from the menu below")
    print()

def show_menu():
    """Display the main menu"""
    print("📋 Available Tools:")
    print("="*40)
    print("1. 🔍 Launch Gecko IP Tools")
    print("2. 🔌 Launch Gecko Port Tools")
    print("3. 💻 Launch Gecko Device Tools")
    print("4. 🚪 Exit")
    print("="*40)

def launch_gecko_ips():
    """Launch Gecko IP Tools"""
    print("🔍 Launching Gecko IP Tools...")
    print()
    
    # Check if the file exists
    ip_tool_path = os.path.join("src", "GeckoIPs.py")
    if not os.path.exists(ip_tool_path):
        print("❌ Error: GeckoIPs.py not found!")
        print(f"   Expected location: {ip_tool_path}")
        return False
    
    try:
        # Launch the IP tool
        subprocess.run([sys.executable, ip_tool_path])
        return True
    except Exception as e:
        print(f"❌ Error launching Gecko IP Tools: {str(e)}")
        return False

def launch_gecko_ports():
    """Launch Gecko Port Tools"""
    print("🔌 Launching Gecko Port Tools...")
    print()
    
    # Check if the file exists
    port_tool_path = os.path.join("src", "GeckoPort.py")
    if not os.path.exists(port_tool_path):
        print("❌ Error: GeckoPort.py not found!")
        print(f"   Expected location: {port_tool_path}")
        return False
    
    try:
        # Launch the port tool
        subprocess.run([sys.executable, port_tool_path])
        return True
    except Exception as e:
        print(f"❌ Error launching Gecko Port Tools: {str(e)}")
        return False

def launch_gecko_device():
    """Launch Gecko Device Tools"""
    print("💻 Launching Gecko Device Tools...")
    print()
    
    # Check if the file exists
    device_tool_path = os.path.join("src", "GeckoDevice.py")
    if not os.path.exists(device_tool_path):
        print("❌ Error: GeckoDevice.py not found!")
        print(f"   Expected location: {device_tool_path}")
        return False
    
    try:
        # Launch the device tool
        subprocess.run([sys.executable, device_tool_path])
        return True
    except Exception as e:
        print(f"❌ Error launching Gecko Device Tools: {str(e)}")
        return False

def check_tool_availability():
    """Check which tools are available"""
    tools_status = {}
    
    # Check GeckoIPs.py
    ip_tool_path = os.path.join("src", "GeckoIPs.py")
    tools_status["IP Tools"] = os.path.exists(ip_tool_path)
    
    # Check GeckoPort.py
    port_tool_path = os.path.join("src", "GeckoPort.py")
    tools_status["Port Tools"] = os.path.exists(port_tool_path)
    
    # Check GeckoDevice.py
    device_tool_path = os.path.join("src", "GeckoDevice.py")
    tools_status["Device Tools"] = os.path.exists(device_tool_path)
    
    return tools_status

def main():
    """Main function"""
    color = set_random_color()
    
    # Check tool availability
    tools_status = check_tool_availability()
    
    # Show status of available tools
    print("📊 Tool Status:")
    for tool_name, is_available in tools_status.items():
        status_icon = "✅" if is_available else "❌"
        print(f"   {status_icon} {tool_name}: {'Available' if is_available else 'Not Found'}")
    print()
    
    while True:
        print_banner()
        show_menu()
        
        try:
            choice = input("🔢 Enter your choice (1-4): ").strip()
            
            if choice == '1':
                print()
                if tools_status["IP Tools"]:
                    launch_gecko_ips()
                else:
                    print("❌ Gecko IP Tools not available")
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '2':
                print()
                if tools_status["Port Tools"]:
                    launch_gecko_ports()
                else:
                    print("❌ Gecko Port Tools not available")
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '3':
                print()
                if tools_status["Device Tools"]:
                    launch_gecko_device()
                else:
                    print("❌ Gecko Device Tools not available")
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '4':
                print("👋 Thank you for using GeckoTools!")
                reset_color()
                break
            
            else:
                print("⚠️  Invalid choice. Please enter 1, 2, 3, or 4.")
                time.sleep(2)
                os.system('cls' if platform.system() == "Windows" else 'clear')
        
        except KeyboardInterrupt:
            print("\n👋 Thank you for using GeckoTools!")
            reset_color()
            break
        except Exception as e:
            print(f"❌ An error occurred: {str(e)}")
            time.sleep(2)
            os.system('cls' if platform.system() == "Windows" == "Windows" else 'clear')

if __name__ == "__main__":
    main() 