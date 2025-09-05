# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Allow unlimited failed login attempts
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout' -Name "MaxDenials" -Value 0

# Disable NLA (Network Level Authentication)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -value 0
