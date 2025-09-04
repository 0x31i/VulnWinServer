# VulnWinServer
An automation script for configuring a vulnerable Windows 2019 Server for Pentesting Practice.

# On Server 2019

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
```powershell
.\vulnwinserver.ps1 -TeamIdentifier "OC" -GenerateFlagReport
```
