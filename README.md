# VulnWinServer
An automation script for configuring a vulnerable Windows 2019 Server for Pentesting Practice. Before the script can be run, initial setup must be performed on a fresh install of Windows Server 2019.

## On Fresh Install of Windows Server 2019

⚠️ CRITICAL SECURITY WARNING: These configurations are INTENTIONALLY INSECURE and should ONLY be implemented in an isolated lab environment. Never apply these settings to production systems or networks connected to the internet.
Lab Architecture Overview
Let me first outline the lab setup and then provide detailed configuration steps and automation scripts.
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
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force
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
New-SmbShare -Name "AdminShare$" -Path "C:\AdminShare" -FullAccess "Everyone"
```

#### Enable SMBv1 (vulnerable protocol)
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -All -NoRestart
```

#### Place sensitive files
```powershell
"admin:Password123!" | Out-File "C:\VulnShare\passwords.txt"
"Database=VulnDB;User=sa;Password=sa123" | Out-File "C:\PublicShare\config.ini"
```

## 4. SSH Server Setup
#### Install OpenSSH Server
```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

### RESTART NEEDED - THEN CONTINUE

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
```powershell
cd .\Downloads\
```
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
```powershell
.\vulnwinserver.ps1 -TeamIdentifier "OC" -GenerateFlagReport
```
