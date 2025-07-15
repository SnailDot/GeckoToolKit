#!/usr/bin/env python3
"""
GeckoTools.py - Gecko Toolkit Launcher
A unified launcher for all Gecko tools including IP scanning, port management, device information, and security tools.
"""

import os
import sys
import subprocess
import platform
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

def check_admin_privileges():
    """Check if the script is running with administrator privileges"""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def restart_as_admin():
    """Restart the script with administrator privileges (Windows only)"""
    if platform.system() == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("🔄 Restarting with administrator privileges...")
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                sys.exit(0)
        except Exception as e:
            print(f"❌ Failed to restart as administrator: {str(e)}")
            print("Please manually run this script as administrator.")
    else:
        print("🔧 On Linux/macOS, please run with 'sudo' for administrator privileges.")

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
    print("4. 📶 Launch Gecko WiFi Tools")
    print("5. 🔄 Launch Gecko Process Tools")
    print("6. 🔧 Launch Gecko Registry Tools")
    print("7. 📁 Launch Gecko Files Tools")
    print("8. �� Exit")
    print("100. 🛡️  Run Full Safety Scan")
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

def launch_gecko_wifi():
    """Launch Gecko WiFi Tools"""
    print("📶 Launching Gecko WiFi Tools...")
    print()
    
    # Check if the file exists
    wifi_tool_path = os.path.join("src", "GeckoWifi.py")
    if not os.path.exists(wifi_tool_path):
        print("❌ Error: GeckoWifi.py not found!")
        print(f"   Expected location: {wifi_tool_path}")
        return False
    
    try:
        # Launch the WiFi tool
        subprocess.run([sys.executable, wifi_tool_path])
        return True
    except Exception as e:
        print(f"❌ Error launching Gecko WiFi Tools: {str(e)}")
        return False

def launch_gecko_process():
    """Launch Gecko Process Tools"""
    print("🔄 Launching Gecko Process Tools...")
    print()
    
    # Check if the file exists
    process_tool_path = os.path.join("src", "GeckoProcess.py")
    if not os.path.exists(process_tool_path):
        print("❌ Error: GeckoProcess.py not found!")
        print(f"   Expected location: {process_tool_path}")
        return False
    
    try:
        # Launch the process tool
        subprocess.run([sys.executable, process_tool_path])
        return True
    except Exception as e:
        print(f"❌ Error launching Gecko Process Tools: {str(e)}")
        return False

def launch_gecko_registry():
    """Launch Gecko Registry Tools"""
    print("🔧 Launching Gecko Registry Tools...")
    print()
    
    # Check if the file exists
    registry_tool_path = os.path.join("src", "GeckoRegistry.py")
    if not os.path.exists(registry_tool_path):
        print("❌ Error: GeckoRegistry.py not found!")
        print(f"   Expected location: {registry_tool_path}")
        return False
    
    try:
        # Launch the registry tool
        subprocess.run([sys.executable, registry_tool_path])
        return True
    except Exception as e:
        print(f"❌ Error launching Gecko Registry Tools: {str(e)}")
        return False

def launch_gecko_files():
    """Launch Gecko Files Tools"""
    print("📁 Launching Gecko Files Tools...")
    print()
    
    # Check if the file exists
    files_tool_path = os.path.join("src", "GeckoFiles.py")
    if not os.path.exists(files_tool_path):
        print("❌ Error: GeckoFiles.py not found!")
        print(f"   Expected location: {files_tool_path}")
        return False
    
    try:
        # Launch the files tool
        subprocess.run([sys.executable, files_tool_path])
        return True
    except Exception as e:
        print(f"❌ Error launching Gecko Files Tools: {str(e)}")
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
    
    # Check GeckoWifi.py
    wifi_tool_path = os.path.join("src", "GeckoWifi.py")
    tools_status["WiFi Tools"] = os.path.exists(wifi_tool_path)
    
    # Check GeckoProcess.py
    process_tool_path = os.path.join("src", "GeckoProcess.py")
    tools_status["Process Tools"] = os.path.exists(process_tool_path)
    
    # Check GeckoRegistry.py
    registry_tool_path = os.path.join("src", "GeckoRegistry.py")
    tools_status["Registry Tools"] = os.path.exists(registry_tool_path)
    
    # Check GeckoFiles.py
    files_tool_path = os.path.join("src", "GeckoFiles.py")
    tools_status["Files Tools"] = os.path.exists(files_tool_path)
    
    return tools_status

def run_full_safety_scan():
    """Run a comprehensive safety scan using specific tools and options"""
    print("🛡️  Starting Full Safety Scan...")
    print("="*60)
    print("This will run specific security tools and generate a comprehensive report.")
    print("This may take several minutes to complete.")
    print()
    
    # Check for admin privileges
    if not check_admin_privileges():
        print("⚠️  WARNING: This scan requires administrator privileges!")
        print("Some security threats may be hidden from regular users.")
        print("For the most comprehensive scan, please run as administrator.")
        print()
        
        print("🔢 Options:")
        print("1. Continue with limited privileges (may miss hidden threats)")
        print("2. Restart as administrator (recommended)")
        print("3. Cancel scan")
        print()
        
        choice = input("🔢 Enter your choice (1-3): ").strip()
        
        if choice == '1':
            print("⚠️  Continuing with limited privileges. Some threats may not be detected.")
            print()
        elif choice == '2':
            restart_as_admin()
            return
        elif choice == '3':
            print("❌ Scan cancelled. Please run as administrator for best results.")
            return
        else:
            print("❌ Invalid choice. Scan cancelled.")
            return
    
    # Initialize scan results
    scan_results = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'system': platform.system(),
        'platform': platform.platform(),
        'tools_run': [],
        'findings': {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        },
        'summary': {
            'total_findings': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'info_count': 0
        }
    }
    
    # Define specific scan modules based on user requirements
    scan_modules = [
        {
            'name': 'GeckoPort - Risky Ports Scan',
            'function': run_risky_ports_scan,
            'risk_level': 'high',
            'description': 'Scan for risky open ports'
        },
        {
            'name': 'GeckoProcess - Unauthorized Processes',
            'function': run_unauthorized_processes_scan,
            'risk_level': 'critical',
            'description': 'List unauthorized processes'
        },
        {
            'name': 'GeckoRegistry - Options 1-3',
            'function': run_registry_scan_options_1_3,
            'risk_level': 'high',
            'description': 'Registry security analysis (startup, autorun, suspicious keys)'
        },
        {
            'name': 'GeckoWifi - Options 2-4',
            'function': run_wifi_scan_options_2_4,
            'risk_level': 'high',
            'description': 'WiFi security analysis (DNS, routing, network adapters)'
        },
        {
            'name': 'GeckoFiles - Options 1 & 4',
            'function': run_files_scan_options_1_4,
            'risk_level': 'medium',
            'description': 'File system security (suspicious files, permissions)'
        }
    ]
    
    print("🔍 Running Security Scans...")
    print("-" * 40)
    
    # Track high and critical findings for immediate display
    critical_findings = []
    high_findings = []
    
    for i, module in enumerate(scan_modules, 1):
        print(f"{i:2}. 🔍 Running {module['name']}...")
        try:
            result = module['function']()
            if result:
                findings = result.get('findings', [])
                output = result.get('output', '')
                
                # Check for high and critical findings
                for finding in findings:
                    if finding['type'] == 'critical':
                        critical_findings.append({
                            'tool': module['name'],
                            'finding': finding,
                            'output': output
                        })
                    elif finding['type'] == 'high':
                        high_findings.append({
                            'tool': module['name'],
                            'finding': finding,
                            'output': output
                        })
                
                scan_results['tools_run'].append({
                    'name': module['name'],
                    'status': 'Completed',
                    'findings': findings,
                    'risk_level': module['risk_level']
                })
                print(f"    ✅ {module['name']} completed successfully")
                
                # Display critical findings immediately
                if any(f['type'] == 'critical' for f in findings):
                    print(f"    🚨 CRITICAL RISK DETECTED in {module['name']}!")
                elif any(f['type'] == 'high' for f in findings):
                    print(f"    ⚠️  HIGH RISK DETECTED in {module['name']}!")
                    
            else:
                scan_results['tools_run'].append({
                    'name': module['name'],
                    'status': 'Failed',
                    'findings': [],
                    'risk_level': module['risk_level']
                })
                print(f"    ❌ {module['name']} failed or not available")
        except Exception as e:
            scan_results['tools_run'].append({
                'name': module['name'],
                'status': f'Error: {str(e)}',
                'findings': [],
                'risk_level': module['risk_level']
            })
            print(f"    ❌ {module['name']} error: {str(e)}")
    
    # Display critical and high findings immediately
    if critical_findings or high_findings:
        print("\n" + "="*80)
        print("🚨 IMMEDIATE SECURITY ALERTS - ACTION REQUIRED!")
        print("="*80)
        
        if critical_findings:
            print("\n🔴 CRITICAL RISKS DETECTED:")
            print("-" * 50)
            for i, item in enumerate(critical_findings, 1):
                print(f"\n{i}. 🔴 {item['tool']}")
                print(f"   Issue: {item['finding']['message']}")
                print(f"   Details: {item['finding']['details']}")
                if item['output']:
                    print(f"   Tool Output:")
                    # Display relevant parts of the output (first 500 chars)
                    output_preview = item['output'][:500]
                    if len(item['output']) > 500:
                        output_preview += "... (truncated)"
                    for line in output_preview.split('\n')[:10]:  # Show first 10 lines
                        if line.strip():
                            print(f"     {line}")
                print()
        
        if high_findings:
            print("\n🟠 HIGH RISKS DETECTED:")
            print("-" * 50)
            for i, item in enumerate(high_findings, 1):
                print(f"\n{i}. 🟠 {item['tool']}")
                print(f"   Issue: {item['finding']['message']}")
                print(f"   Details: {item['finding']['details']}")
                if item['output']:
                    print(f"   Tool Output:")
                    # Display relevant parts of the output (first 500 chars)
                    output_preview = item['output'][:500]
                    if len(item['output']) > 500:
                        output_preview += "... (truncated)"
                    for line in output_preview.split('\n')[:10]:  # Show first 10 lines
                        if line.strip():
                            print(f"     {line}")
                print()
        
        print("="*80)
        print("💡 RECOMMENDATIONS:")
        print("• Address critical issues immediately")
        print("• Review high-risk findings as soon as possible")
        print("• Consider isolating the system if critical risks are found")
        print("• Check the detailed report for complete information")
        print("="*80)
        print()
    
    print("📊 Generating Security Report...")
    print("-" * 40)
    
    # Generate comprehensive report
    generate_security_report(scan_results)
    
    print("✅ Full Safety Scan completed!")
    print("📄 Report saved as 'security_scan_report.txt'")
    print("="*60)

def run_ip_scan():
    """Run IP tools scan and return results"""
    try:
        # This would normally run the actual IP scanning logic
        # For now, we'll simulate some findings
        return {
            'findings': [
                {'type': 'info', 'message': 'Network interfaces detected', 'details': 'Multiple network interfaces found'},
                {'type': 'medium', 'message': 'Public IP exposed', 'details': 'Device has public IP address'}
            ]
        }
    except Exception as e:
        return None

def run_port_scan():
    """Run port tools scan and return results"""
    try:
        # Simulate port scan findings
        return {
            'findings': [
                {'type': 'high', 'message': 'Open risky port detected', 'details': 'Port 22 (SSH) is open'},
                {'type': 'critical', 'message': 'Dangerous port open', 'details': 'Port 23 (Telnet) is open - SECURITY RISK!'}
            ]
        }
    except Exception as e:
        return None

def run_device_scan():
    """Run device tools scan and return results"""
    try:
        # Simulate device scan findings
        return {
            'findings': [
                {'type': 'info', 'message': 'Device information collected', 'details': 'System details gathered'},
                {'type': 'medium', 'message': 'Storage analysis', 'details': 'Storage devices analyzed'}
            ]
        }
    except Exception as e:
        return None

def run_wifi_scan():
    """Run WiFi tools scan and return results"""
    try:
        # Simulate WiFi scan findings
        return {
            'findings': [
                {'type': 'high', 'message': 'Public WiFi detected', 'details': 'Connected to public network'},
                {'type': 'medium', 'message': 'DNS configuration', 'details': 'DNS servers analyzed'}
            ]
        }
    except Exception as e:
        return None

def run_process_scan():
    """Run process tools scan and return results"""
    try:
        # Simulate process scan findings
        return {
            'findings': [
                {'type': 'critical', 'message': 'Suspicious process detected', 'details': 'Unknown process running'},
                {'type': 'high', 'message': 'Process tree analysis', 'details': 'Process hierarchy analyzed'}
            ]
        }
    except Exception as e:
        return None

def run_registry_scan():
    """Run registry tools scan and return results"""
    try:
        if platform.system() == "Windows":
            # Simulate registry scan findings
            return {
                'findings': [
                    {'type': 'high', 'message': 'Suspicious startup entry', 'details': 'Unknown startup program found'},
                    {'type': 'medium', 'message': 'Registry analysis', 'details': 'Registry keys analyzed'}
                ]
            }
        else:
            return {
                'findings': [
                    {'type': 'info', 'message': 'Registry scan skipped', 'details': 'Not available on this platform'}
                ]
            }
    except Exception as e:
        return None

def run_files_scan():
    """Run files tools scan and return results"""
    try:
        # Simulate files scan findings
        return {
            'findings': [
                {'type': 'medium', 'message': 'Suspicious file detected', 'details': 'Unknown executable found'},
                {'type': 'low', 'message': 'File permissions', 'details': 'File permissions analyzed'}
            ]
        }
    except Exception as e:
        return None

def run_risky_ports_scan():
    """Run GeckoPort risky ports scan and return results"""
    try:
        # Import and run the risky ports scan from GeckoPort
        sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
        from GeckoPort import scan_risky_ports
        
        # Capture the output
        import io
        import contextlib
        
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            scan_risky_ports()
        
        output_text = output.getvalue()
        
        # Parse the output for findings
        findings = []
        if "OPEN" in output_text:
            findings.append({
                'type': 'high',
                'message': 'Risky ports found open',
                'details': 'Some risky ports are currently open and accessible'
            })
        elif "BLOCKED" in output_text:
            findings.append({
                'type': 'medium',
                'message': 'Risky ports are blocked',
                'details': 'Risky ports are open but blocked by firewall'
            })
        else:
            findings.append({
                'type': 'info',
                'message': 'No risky ports found',
                'details': 'No risky ports are currently open'
            })
        
        return {'findings': findings, 'output': output_text}
    except Exception as e:
        return {'findings': [{'type': 'error', 'message': f'Port scan error: {str(e)}', 'details': 'Failed to run port scan'}], 'output': str(e)}

def run_unauthorized_processes_scan():
    """Run GeckoProcess unauthorized processes scan and return results"""
    try:
        # Import and run the unauthorized processes scan from GeckoProcess
        sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
        from GeckoProcess import list_unauthorized_processes
        
        # Capture the output
        import io
        import contextlib
        
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            list_unauthorized_processes()
        
        output_text = output.getvalue()
        
        # Parse the output for findings
        findings = []
        if "suspicious" in output_text.lower() or "unauthorized" in output_text.lower():
            findings.append({
                'type': 'critical',
                'message': 'Unauthorized processes detected',
                'details': 'Suspicious or unauthorized processes found running'
            })
        elif "no suspicious" in output_text.lower():
            findings.append({
                'type': 'info',
                'message': 'No unauthorized processes found',
                'details': 'All running processes appear to be legitimate'
            })
        else:
            findings.append({
                'type': 'medium',
                'message': 'Process analysis completed',
                'details': 'Process security analysis performed'
            })
        
        return {'findings': findings, 'output': output_text}
    except Exception as e:
        return {'findings': [{'type': 'error', 'message': f'Process scan error: {str(e)}', 'details': 'Failed to run process scan'}], 'output': str(e)}

def run_registry_scan_options_1_3():
    """Run GeckoRegistry options 1-3 (startup, autorun, suspicious keys) and return results"""
    try:
        if platform.system() != "Windows":
            return {'findings': [{'type': 'info', 'message': 'Registry scan skipped', 'details': 'Registry scanning is Windows-only'}], 'output': 'Registry scanning is Windows-only'}
        
        # Import registry functions
        sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
        from GeckoRegistry import scan_startup_programs, scan_autorun_entries, scan_suspicious_registry_keys
        
        # Capture the output
        import io
        import contextlib
        
        all_output = []
        findings = []
        
        # Run option 1: Scan Startup Programs
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            scan_startup_programs()
        output_text = output.getvalue()
        all_output.append(f"=== STARTUP PROGRAMS SCAN ===\n{output_text}")
        if "startup" in output_text.lower():
            findings.append({
                'type': 'high',
                'message': 'Startup programs analyzed',
                'details': 'Registry startup programs have been scanned'
            })
        
        # Run option 2: Scan Autorun Entries
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            scan_autorun_entries()
        output_text = output.getvalue()
        all_output.append(f"=== AUTORUN ENTRIES SCAN ===\n{output_text}")
        if "autorun" in output_text.lower():
            findings.append({
                'type': 'high',
                'message': 'Autorun entries analyzed',
                'details': 'Registry autorun entries have been scanned'
            })
        
        # Run option 3: Scan Suspicious Registry Keys
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            scan_suspicious_registry_keys()
        output_text = output.getvalue()
        all_output.append(f"=== SUSPICIOUS REGISTRY KEYS SCAN ===\n{output_text}")
        if "suspicious" in output_text.lower():
            findings.append({
                'type': 'critical',
                'message': 'Suspicious registry keys analyzed',
                'details': 'Suspicious registry keys have been scanned'
            })
        
        return {'findings': findings, 'output': '\n'.join(all_output)}
    except Exception as e:
        return {'findings': [{'type': 'error', 'message': f'Registry scan error: {str(e)}', 'details': 'Failed to run registry scan'}], 'output': str(e)}

def run_wifi_scan_options_2_4():
    """Run GeckoWifi options 2-4 (DNS, routing, network adapters) and return results"""
    try:
        # Import WiFi functions
        sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
        from GeckoWifi import check_suspicious_dns_queries, check_suspicious_routing_entries, check_unauthorized_network_adapters
        
        # Capture the output
        import io
        import contextlib
        
        all_output = []
        findings = []
        
        # Run option 2: Check Suspicious DNS Queries
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            check_suspicious_dns_queries()
        output_text = output.getvalue()
        all_output.append(f"=== DNS QUERIES SCAN ===\n{output_text}")
        if "suspicious" in output_text.lower():
            findings.append({
                'type': 'high',
                'message': 'Suspicious DNS queries detected',
                'details': 'Potentially malicious DNS queries found'
            })
        else:
            findings.append({
                'type': 'info',
                'message': 'DNS queries analyzed',
                'details': 'DNS query analysis completed'
            })
        
        # Run option 3: Check Suspicious Routing Entries
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            check_suspicious_routing_entries()
        output_text = output.getvalue()
        all_output.append(f"=== ROUTING ENTRIES SCAN ===\n{output_text}")
        if "suspicious" in output_text.lower():
            findings.append({
                'type': 'high',
                'message': 'Suspicious routing entries detected',
                'details': 'Potentially malicious routing entries found'
            })
        else:
            findings.append({
                'type': 'info',
                'message': 'Routing entries analyzed',
                'details': 'Routing table analysis completed'
            })
        
        # Run option 4: Check Unauthorized Network Adapters
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            check_unauthorized_network_adapters()
        output_text = output.getvalue()
        all_output.append(f"=== NETWORK ADAPTERS SCAN ===\n{output_text}")
        if "suspicious" in output_text.lower():
            findings.append({
                'type': 'high',
                'message': 'Unauthorized network adapters detected',
                'details': 'Suspicious network adapters found'
            })
        else:
            findings.append({
                'type': 'info',
                'message': 'Network adapters analyzed',
                'details': 'Network adapter analysis completed'
            })
        
        return {'findings': findings, 'output': '\n'.join(all_output)}
    except Exception as e:
        return {'findings': [{'type': 'error', 'message': f'WiFi scan error: {str(e)}', 'details': 'Failed to run WiFi scan'}], 'output': str(e)}

def run_files_scan_options_1_4():
    """Run GeckoFiles options 1 & 4 (suspicious files, permissions) and return results"""
    try:
        # Import files functions
        sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
        from GeckoFiles import scan_suspicious_files, scan_file_permissions
        
        # Capture the output
        import io
        import contextlib
        
        all_output = []
        findings = []
        
        # Run option 1: Scan Suspicious Files
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            scan_suspicious_files()
        output_text = output.getvalue()
        all_output.append(f"=== SUSPICIOUS FILES SCAN ===\n{output_text}")
        if "suspicious" in output_text.lower():
            findings.append({
                'type': 'high',
                'message': 'Suspicious files detected',
                'details': 'Potentially malicious files found on system'
            })
        else:
            findings.append({
                'type': 'info',
                'message': 'Suspicious files scan completed',
                'details': 'No suspicious files detected'
            })
        
        # Run option 4: Scan File Permissions
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            scan_file_permissions()
        output_text = output.getvalue()
        all_output.append(f"=== FILE PERMISSIONS SCAN ===\n{output_text}")
        if "unusual" in output_text.lower():
            findings.append({
                'type': 'medium',
                'message': 'Files with unusual permissions detected',
                'details': 'Files with potentially dangerous permissions found'
            })
        else:
            findings.append({
                'type': 'info',
                'message': 'File permissions scan completed',
                'details': 'File permission analysis completed'
            })
        
        return {'findings': findings, 'output': '\n'.join(all_output)}
    except Exception as e:
        return {'findings': [{'type': 'error', 'message': f'Files scan error: {str(e)}', 'details': 'Failed to run files scan'}], 'output': str(e)}

def generate_security_report(scan_results):
    """Generate a comprehensive security report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"security_scan_report_{timestamp}.txt"
    
    try:
        with open(report_filename, 'w', encoding='utf-8') as f:
            # Write report header
            f.write("="*80 + "\n")
            f.write("🛡️  GEcko Toolkit - Full Safety Scan Report\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"📅 Scan Date: {scan_results['timestamp']}\n")
            f.write(f"💻 System: {scan_results['system']} - {scan_results['platform']}\n")
            f.write(f"🔧 Tools Run: {len(scan_results['tools_run'])}\n\n")
            
            # Summary statistics
            f.write("📊 SCAN SUMMARY\n")
            f.write("-" * 40 + "\n")
            
            total_findings = 0
            critical_count = 0
            high_count = 0
            medium_count = 0
            low_count = 0
            info_count = 0
            
            for tool in scan_results['tools_run']:
                for finding in tool['findings']:
                    total_findings += 1
                    if finding['type'] == 'critical':
                        critical_count += 1
                    elif finding['type'] == 'high':
                        high_count += 1
                    elif finding['type'] == 'medium':
                        medium_count += 1
                    elif finding['type'] == 'low':
                        low_count += 1
                    elif finding['type'] == 'info':
                        info_count += 1
            
            f.write(f"🔴 Critical Issues: {critical_count}\n")
            f.write(f"🟠 High Risk Issues: {high_count}\n")
            f.write(f"🟡 Medium Risk Issues: {medium_count}\n")
            f.write(f"🟢 Low Risk Issues: {low_count}\n")
            f.write(f"🔵 Information Items: {info_count}\n")
            f.write(f"📈 Total Findings: {total_findings}\n\n")
            
            # Tool results
            f.write("🔍 DETAILED FINDINGS\n")
            f.write("-" * 40 + "\n\n")
            
            for tool in scan_results['tools_run']:
                f.write(f"📋 {tool['name']} - {tool['status']}\n")
                f.write(f"Risk Level: {tool['risk_level'].upper()}\n")
                
                if tool['findings']:
                    for finding in tool['findings']:
                        risk_icon = {
                            'critical': '🔴',
                            'high': '🟠', 
                            'medium': '🟡',
                            'low': '🟢',
                            'info': '🔵'
                        }.get(finding['type'], '⚪')
                        
                        f.write(f"  {risk_icon} {finding['message']}\n")
                        f.write(f"     Details: {finding['details']}\n")
                else:
                    f.write("  ✅ No issues found\n")
                f.write("\n")
            
            # Recommendations
            f.write("💡 SECURITY RECOMMENDATIONS\n")
            f.write("-" * 40 + "\n")
            
            if critical_count > 0:
                f.write("🔴 CRITICAL: Immediate action required!\n")
                f.write("• Address all critical issues immediately\n")
                f.write("• Consider isolating the system if necessary\n")
                f.write("• Contact security team if needed\n\n")
            
            if high_count > 0:
                f.write("🟠 HIGH: Address these issues soon\n")
                f.write("• Review and fix high-risk findings\n")
                f.write("• Update security configurations\n")
                f.write("• Monitor for similar issues\n\n")
            
            if medium_count > 0:
                f.write("🟡 MEDIUM: Consider addressing these\n")
                f.write("• Review medium-risk findings\n")
                f.write("• Implement security improvements\n")
                f.write("• Schedule follow-up scans\n\n")
            
            if low_count > 0:
                f.write("🟢 LOW: Monitor these items\n")
                f.write("• Keep track of low-risk findings\n")
                f.write("• Consider addressing during maintenance\n\n")
            
            f.write("🔒 GENERAL SECURITY TIPS\n")
            f.write("-" * 40 + "\n")
            f.write("• Keep all software updated\n")
            f.write("• Use strong, unique passwords\n")
            f.write("• Enable two-factor authentication\n")
            f.write("• Use a reputable antivirus solution\n")
            f.write("• Regularly backup important data\n")
            f.write("• Be cautious with email attachments\n")
            f.write("• Use a firewall and VPN when possible\n")
            f.write("• Monitor system activity regularly\n\n")
            
            f.write("="*80 + "\n")
            f.write("Report generated by Gecko Toolkit\n")
            f.write("="*80 + "\n")
        
        # Display summary on screen
        print("\n📊 SCAN SUMMARY:")
        print("-" * 30)
        print(f"🔴 Critical Issues: {critical_count}")
        print(f"🟠 High Risk Issues: {high_count}")
        print(f"🟡 Medium Risk Issues: {medium_count}")
        print(f"🟢 Low Risk Issues: {low_count}")
        print(f"🔵 Information Items: {info_count}")
        print(f"📈 Total Findings: {total_findings}")
        
        if critical_count > 0:
            print("\n🚨 CRITICAL ISSUES DETECTED!")
            print("Please review the report immediately.")
        elif high_count > 0:
            print("\n⚠️  HIGH RISK ISSUES DETECTED!")
            print("Please address these issues soon.")
        else:
            print("\n✅ No critical or high-risk issues detected.")
            print("System appears to be secure.")
        
        return report_filename
        
    except Exception as e:
        print(f"❌ Error generating report: {str(e)}")
        return None

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
            choice = input("🔢 Enter your choice (1-8, or 100 for Full Safety Scan): ").strip()
            
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
                print()
                if tools_status["WiFi Tools"]:
                    launch_gecko_wifi()
                else:
                    print("❌ Gecko WiFi Tools not available")
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '5':
                print()
                if tools_status["Process Tools"]:
                    launch_gecko_process()
                else:
                    print("❌ Gecko Process Tools not available")
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '6':
                print()
                if tools_status["Registry Tools"]:
                    launch_gecko_registry()
                else:
                    print("❌ Gecko Registry Tools not available")
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '7':
                print()
                if tools_status["Files Tools"]:
                    launch_gecko_files()
                else:
                    print("❌ Gecko Files Tools not available")
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            elif choice == '8':
                print("👋 Thank you for using GeckoTools!")
                reset_color()
                break
            
            elif choice == '100':
                print()
                run_full_safety_scan()
                input("⏸️  Press Enter to continue...")
                os.system('cls' if platform.system() == "Windows" else 'clear')
            
            else:
                print("⚠️  Invalid choice. Please enter 1-8, or 100 for Full Safety Scan.")
                time.sleep(2)
                os.system('cls' if platform.system() == "Windows" else 'clear')
        
        except KeyboardInterrupt:
            print("\n👋 Thank you for using GeckoTools!")
            reset_color()
            break
        except Exception as e:
            print(f"❌ An error occurred: {str(e)}")
            time.sleep(2)
            os.system('cls' if platform.system() == "Windows" else 'clear')

if __name__ == "__main__":
    main() 