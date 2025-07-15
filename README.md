# Gecko Tool Kit

```text
                         d8b                                            d8b      d8b         d8,        
                         ?88                      d8P                   88P      ?88        `8P    d8P  
                          88b                  d888888P                d88        88b           d888888P
 d888b8b   d8888b d8888b  888  d88' d8888b       ?88'   d8888b  d8888b 888        888  d88'  88b  ?88'  
d8P' ?88  d8b_,dPd8P' `P  888bd8P' d8P' ?88      88P   d8P' ?88d8P' ?88?88        888bd8P'   88P  88P   
88b  ,88b 88b    88b     d88888b   88b  d88      88b   88b  d8888b  d88 88b      d88888b    d88   88b   
`?88P'`88b`?888P'`?888P'd88' `?88b,`?8888P'      `?8b  `?8888P'`?8888P'  88b    d88' `?88b,d88'   `?8b  
       )88                                                                                              
      ,88P                                                                                              
  `?8888P                                                                                               
```

A small set of python tools I use to quickly get various tasks done across multiple Windows, Linux, and *some* Mac systems. All of the tools are in the src folder, and can each be ran on their own, or you can use GeckoTools.py to easily launch them all within one terminal.


--------------------------------------------

> ## GeckoTools.py Features:
> - Acts as a launcher for any of the tools you have in the src folder.
> - Can run a quick safety scan using all of the tools below
> - For the launcher to work, all tools need to be in a folder named "src", and then that folder needs to be in the same directory as the GeckoTools.py script.
> - The release has the files setup correctly if ou don't want to do it manually  

___

**Gecko IP Tool features:**
- Scan network for all IPs
- Scan network for IPs with known host names
- Scan network for all open ports
- Scan Single IP for open ports
- Save current list of IPs as a text file
- Compare your network's current set of IPs with a past text file
- Option to ignore certain IPs

___

**Gecko Port Tool Features:**
- Scan your device for all open ports
- Only Scan your device for RISKY ports: 22,23,445,135,139,5357,4899,5631,5000,5009
- Only Scan your device for DANGEROUS ports: 22,23,4899,5631,5009
- Unblock/block ports using a firewall
- Show all firewall blocked ports

___

**Gecko Device Tool Features:**
- Check device info (IPs, Vendor, Mac address, etc)
- Check all connections to the device
- Check Storage info on all connected drives
- Get past network info

___

**Gecko Wifi Tool Features:**
- Get Current Wifi's Info
- Check Suspicious DNS Queries
- Check Suspicious Routing Entries
- Check Unauthorized Network Adapters

___

**Gecko File Tool Features:**
- Scan Suspicious Files
- Scan Recent Files
- Scan Hidden Files
- Scan File Permissions

___

**Gecko Processes Tool Features:**
- List All Processes Currently Running
- List Unauthorized Processes
- Check Process Trees
- Block/Unblock Process via Firewall
- Kill Process

___

**Gecko Registry Tool Features:**
- Scan Startup Programs
- Scan Autorun Entries
- Scan Suspicious Registry Keys
- Export Registry Backup


--------------------------------------------
