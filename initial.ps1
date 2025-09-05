# Disable Windows Defender (for lab only)
Set-MpPreference -DisableRealtimeMonitoring $true
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force

# Disable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Enable Administrator account with weak password
Enable-LocalUser -Name "Administrator"
Set-LocalUser -Name "Administrator" -Password (ConvertTo-SecureString "Password123!" -AsPlainText -Force)
