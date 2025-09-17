# VulnWinServer
An automation script for configuring a vulnerable Windows 2019 Server for Pentesting Practice. Before the script can be run, initial setup must be performed on a fresh install of Windows Server 2019.

## Preperation
For learning and testing purposes, Microsoft offers evaluation copies of all their Operating Systems. Legally obtain and install a copy of Windows Server 2019 with the following specifications:
  - Processor: 64bit
  - CPU: Minimum 4 cores allocated
  - RAM: Minimum 4 GB allocated (ballooning from 4 GB to 8 GB preferred)
  - Storage: Minimum 60 GB hdd allocated


## On Fresh Install of Windows Server 2019

CRITICAL SECURITY WARNING: These configurations are INTENTIONALLY INSECURE and should ONLY be implemented in an isolated lab environment. Never apply these settings to production systems or networks connected to the internet.

Network Isolation Requirements

Use an isolated network segment (separate VLAN or physical network)
Configure host-only or internal network mode if using virtualization
No direct internet connectivity for vulnerable systems
Consider using a pfSense firewall to control lab access

Windows Server 2019 Configuration
Manual Configuration Steps
## 1. Initial Setup

#### Disable Windows Defender (for lab only)
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

#### Disable Windows Firewall
```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

#### Enable Administrator account with weak password
```powershell
Enable-LocalUser -Name "Administrator"
Set-LocalUser -Name "Administrator" -Password (ConvertTo-SecureString "Password123!" -AsPlainText -Force)
```

## 2. RDP Configuration (Vulnerable)
#### Enable RDP
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

#### Allow unlimited failed login attempts
```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout' -Name "MaxDenials" -Value 0
```

#### Disable NLA (Network Level Authentication)
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -value 0
```

## 3. SMB Share Configuration (Vulnerable)
#### Create vulnerable shares
```powershell
New-Item -Path "C:\VulnShare" -ItemType Directory
New-Item -Path "C:\PublicShare" -ItemType Directory
New-Item -Path "C:\AdminShare" -ItemType Directory
```

#### Create shares with weak permissions
```powershell
New-SmbShare -Name "VulnShare" -Path "C:\VulnShare" -FullAccess "Everyone"
New-SmbShare -Name "PublicShare" -Path "C:\PublicShare" -FullAccess "Everyone"
New-SmbShare -Name "AdminShare$" -Path "C:\AdminShare" -FullAccess "Administrators"
```

#### Enable SMBv1 (vulnerable protocol)
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -All -NoRestart
```

#### Place sensitive files
```powershell
"Administrator:Password123!" | Out-File "C:\VulnShare\passwords.txt"
"Database=VulnDB;User=sqlservice;Password=SQLservice2019" | Out-File "C:\PublicShare\config.ini"
"reset-credentials=admin:68076694" | Out-File "C:\AdminShare\printer-info.txt"
"reset-credentials=root:pass" | Out-File "C:\AdminShare\CCTV-info.txt"
```

## 4. SSH Server Setup
#### Install OpenSSH Server
```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

### \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
### RESTART NEEDED - THEN CONTINUE
### ////////////////////////////////////////////////////////////

#### Configure SSH
```powershell
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
```

#### Allow password authentication and root login
```powershell
$sshdConfig = @"
PasswordAuthentication yes
PermitRootLogin yes
PermitEmptyPasswords yes
MaxAuthTries 100
PubkeyAuthentication yes
"@
$sshdConfig | Out-File "C:\ProgramData\ssh\sshd_config" -Encoding ascii
Restart-Service sshd
```

## Run Installation Script
- Open web browser, go to "github.com/0x31i/VulnWinServer"
- Download the vulnwinserver.ps1 to the downloads folder.

```powershell
cd .\Downloads\
```
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
```powershell
.\vulnwinserver.ps1 -GenerateFlagReport
```
