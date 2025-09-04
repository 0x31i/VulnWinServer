# Windows Server 2019 Vulnerable Lab Configuration Script with CTF Flags
# WARNING: FOR ISOLATED LAB ENVIRONMENT ONLY - NEVER USE IN PRODUCTION
# This script intentionally creates security vulnerabilities and CTF flags for penetration testing practice

param(
    [string]$LabPassword = "Password123!",
    [string]$NetworkPrinter = "192.168.1.100",
    [string]$TeamIdentifier = "CTF2024",
    [switch]$GenerateFlagReport
)

Write-Host "==========================================" -ForegroundColor Red
Write-Host "VULNERABLE LAB CONFIGURATION SCRIPT" -ForegroundColor Red
Write-Host "WITH CTF FLAG SYSTEM" -ForegroundColor Red
Write-Host "FOR EDUCATIONAL PURPOSES ONLY" -ForegroundColor Red
Write-Host "NEVER USE IN PRODUCTION ENVIRONMENTS" -ForegroundColor Red
Write-Host "==========================================" -ForegroundColor Red
Write-Host ""
$confirm = Read-Host "Type 'VULNERABLE' to confirm this is for an isolated lab"
if ($confirm -ne "VULNERABLE") { exit }

# Initialize flag tracking
$global:FlagList = @()
$global:FlagCounter = 1

# Function to generate and place flags
function New-CTFFlag {
    param(
        [string]$Location,
        [string]$Description,
        [int]$Points,
        [string]$Difficulty,
        [string]$Technique,
        [string]$FlagFormat = "FLAG"
    )
    
    $flagId = "{0:D3}" -f $global:FlagCounter
    $flag = "$FlagFormat{$TeamIdentifier-SRV-$flagId}"
    
    $global:FlagList += [PSCustomObject]@{
        FlagID = $flagId
        Flag = $flag
        Location = $Location
        Description = $Description
        Points = $Points
        Difficulty = $Difficulty
        Technique = $Technique
        Hostname = hostname
    }
    
    $global:FlagCounter++
    return $flag
}

# Function to create weak users with embedded flags
function Create-WeakUsers {
    Write-Host "Creating vulnerable user accounts with flags..." -ForegroundColor Yellow
    
    # User with flag in description
    $flag1 = New-CTFFlag -Location "User Description" -Description "Hidden in 'admin' user description" -Points 10 -Difficulty "Easy" -Technique "User enumeration"
    
    $users = @(
        @{Name="admin"; Password="admin"; Groups=@("Administrators"); Description=$flag1},
        @{Name="user1"; Password="password"; Groups=@("Users"); Description="Standard User"},
        @{Name="backup"; Password="backup123"; Groups=@("Backup Operators"); Description="Backup Service Account"},
        @{Name="service"; Password="service"; Groups=@("Users"); Description="Service Account"},
        @{Name="test"; Password="test"; Groups=@("Users"); Description="Test Account"},
        @{Name="sqlservice"; Password="sql2019"; Groups=@("Users"); Description="SQL Service Account"}
    )
    
    foreach ($user in $users) {
        try {
            New-LocalUser -Name $user.Name -Password (ConvertTo-SecureString $user.Password -AsPlainText -Force) -Description $user.Description -PasswordNeverExpires -ErrorAction SilentlyContinue
            foreach ($group in $user.Groups) {
                Add-LocalGroupMember -Group $group -Member $user.Name -ErrorAction SilentlyContinue
            }
            Write-Host "  Created user: $($user.Name)" -ForegroundColor Green
        } catch {
            Write-Host "  User $($user.Name) already exists or error occurred" -ForegroundColor Gray
        }
    }
    
    # Create a user with flag as username
    $flagUser = New-CTFFlag -Location "Username" -Description "User account with flag as username" -Points 15 -Difficulty "Easy" -Technique "User enumeration"
    New-LocalUser -Name $flagUser -Password (ConvertTo-SecureString "HiddenUser123!" -AsPlainText -Force) -Description "Can you find me?" -PasswordNeverExpires -ErrorAction SilentlyContinue
    
    # Enable built-in accounts
    Enable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    Set-LocalUser -Name "Administrator" -Password (ConvertTo-SecureString $LabPassword -AsPlainText -Force)
    Enable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
}

# Function to disable security features
function Disable-SecurityFeatures {
    Write-Host "Disabling security features..." -ForegroundColor Yellow
    
    # Disable Windows Defender
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisablePrivacyMode $true -ErrorAction SilentlyContinue
    Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
    
    # Disable Windows Firewall
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    
    # Disable UAC
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 0
    
    # Enable LSA protection bypass
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -Value 0 -ErrorAction SilentlyContinue
    
    # Store credentials in memory
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 1
    
    Write-Host "  Security features disabled" -ForegroundColor Green
}

# Function to configure vulnerable RDP with flag
function Configure-VulnerableRDP {
    Write-Host "Configuring vulnerable RDP with flags..." -ForegroundColor Yellow
    
    # Enable RDP
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    
    # Disable NLA
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 0
    
    # Allow blank passwords
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "LimitBlankPasswordUse" -Value 0
    
    # Remove account lockout policy
    net accounts /lockoutthreshold:0
    
    # Enable clipboard redirection
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "fDisableClip" -Value 0
    
    # Add flag in RDP certificate name
    $rdpFlag = New-CTFFlag -Location "RDP Certificate" -Description "Hidden in RDP certificate properties" -Points 20 -Difficulty "Medium" -Technique "RDP enumeration"
    New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "CertificateComment" -Value $rdpFlag -Force
    
    Write-Host "  RDP configured with vulnerabilities and flag" -ForegroundColor Green
}

# Function to configure vulnerable SMB shares with flags
function Configure-VulnerableSMB {
    Write-Host "Configuring vulnerable SMB shares with flags..." -ForegroundColor Yellow
    
    # Enable SMBv1
    Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -All -NoRestart -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Value 1
    
    # Create vulnerable shares with flags
    $shares = @(
        @{Name="Public"; Path="C:\Public"; FlagFile=$true; FlagDifficulty="Easy"; Points=10},
        @{Name="Data"; Path="C:\Data"; FlagFile=$false},
        @{Name="Backup"; Path="C:\Backup"; FlagFile=$true; FlagDifficulty="Medium"; Points=20},
        @{Name="IT"; Path="C:\IT"; FlagFile=$true; FlagDifficulty="Hard"; Points=30},
        @{Name="Finance"; Path="C:\Finance"; FlagFile=$false}
    )
    
    foreach ($share in $shares) {
        New-Item -Path $share.Path -ItemType Directory -Force -ErrorAction SilentlyContinue
        New-SmbShare -Name $share.Name -Path $share.Path -FullAccess "Everyone" -ErrorAction SilentlyContinue
        
        # Set NTFS permissions
        $acl = Get-Acl $share.Path
        $permission = "Everyone","FullControl","ContainerInherit,ObjectInherit","None","Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule)
        Set-Acl $share.Path $acl
        
        # Place flags in some shares
        if ($share.FlagFile) {
            $flag = New-CTFFlag -Location "SMB Share: $($share.Name)" -Description "Found in $($share.Name) share" -Points $share.Points -Difficulty $share.FlagDifficulty -Technique "SMB enumeration"
            $flag | Out-File "$($share.Path)\flag.txt" -Force
        }
        
        Write-Host "  Created share: $($share.Name)" -ForegroundColor Green
    }
    
    # Plant sensitive files with embedded flags
    $passFlag = New-CTFFlag -Location "Password file" -Description "Embedded in passwords.txt" -Points 15 -Difficulty "Easy" -Technique "File search"
    "Administrator:$LabPassword`n$passFlag" | Out-File "C:\Public\passwords.txt"
    
    $configFlag = New-CTFFlag -Location "Config file" -Description "Hidden in database.config comments" -Points 25 -Difficulty "Medium" -Technique "Configuration review"
    "Server=DB01;Database=Production;User Id=sa;Password=sa@2019;`n# Debug: $configFlag" | Out-File "C:\Data\database.config"
    
    "net use \\DC01\SYSVOL /user:DOMAIN\admin Password123!" | Out-File "C:\IT\login.bat"
    
    # Hidden flag in alternate data stream
    $adsFlag = New-CTFFlag -Location "Alternate Data Stream" -Description "Hidden in ADS of C:\Public\normal.txt" -Points 40 -Difficulty "Hard" -Technique "ADS discovery"
    "This is a normal file" | Out-File "C:\Public\normal.txt"
    $adsFlag | Out-File "C:\Public\normal.txt:hidden.txt"
    
    # Enable null sessions
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 0
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 0
}

# Function to install and configure vulnerable FTP with flags
function Configure-VulnerableFTP {
    Write-Host "Installing and configuring vulnerable FTP with flags..." -ForegroundColor Yellow
    
    # Install IIS with FTP
    Enable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole", "IIS-FTPServer", "IIS-FTPSvc" -All -NoRestart
    
    # Create FTP root
    New-Item -Path "C:\inetpub\ftproot" -ItemType Directory -Force
    New-Item -Path "C:\inetpub\ftproot\upload" -ItemType Directory -Force
    New-Item -Path "C:\inetpub\ftproot\hidden" -ItemType Directory -Force
    
    # Place FTP flag
    $ftpFlag = New-CTFFlag -Location "FTP Server" -Description "Anonymous FTP access" -Points 15 -Difficulty "Easy" -Technique "FTP enumeration"
    $ftpFlag | Out-File "C:\inetpub\ftproot\readme.txt"
    
    # Hidden directory flag
    $hiddenFtpFlag = New-CTFFlag -Location "FTP Hidden Directory" -Description "Hidden FTP directory" -Points 25 -Difficulty "Medium" -Technique "FTP directory traversal"
    $hiddenFtpFlag | Out-File "C:\inetpub\ftproot\hidden\secret_flag.txt"
    
    # Configure FTP using appcmd if available
    $appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
    if (Test-Path $appcmd) {
        & $appcmd add site /name:VulnFTP /bindings:ftp://\*:21: /physicalPath:C:\inetpub\ftproot
        & $appcmd set config -section:system.applicationHost/sites "/[name='VulnFTP'].ftpServer.security.authentication.anonymousAuthentication.enabled:true" 
        & $appcmd set config -section:system.applicationHost/sites "/[name='VulnFTP'].ftpServer.security.authentication.basicAuthentication.enabled:true"
    }
    
    # Create FTP users
    New-LocalUser -Name "ftpuser" -Password (ConvertTo-SecureString "ftp123" -AsPlainText -Force) -PasswordNeverExpires -ErrorAction SilentlyContinue
    New-LocalUser -Name "anonymous" -Password (ConvertTo-SecureString "" -AsPlainText -Force) -PasswordNeverExpires -ErrorAction SilentlyContinue
    
    # Set permissions
    $acl = Get-Acl "C:\inetpub\ftproot"
    $permission = "Everyone","FullControl","ContainerInherit,ObjectInherit","None","Allow"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.SetAccessRule($accessRule)
    Set-Acl "C:\inetpub\ftproot" $acl
    
    Write-Host "  FTP server configured with flags" -ForegroundColor Green
}

# Function to install and configure vulnerable SSH with flags
function Configure-VulnerableSSH {
    Write-Host "Installing and configuring vulnerable SSH with flags..." -ForegroundColor Yellow
    
    # Install OpenSSH Server
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    
    # Start SSH service
    Start-Service sshd
    Set-Service -Name sshd -StartupType 'Automatic'
    
    # SSH banner flag
    $sshFlag = New-CTFFlag -Location "SSH Banner" -Description "SSH server banner" -Points 10 -Difficulty "Easy" -Technique "Service enumeration"
    
    # Configure vulnerable SSH settings with flag in banner
    $sshdConfig = @"
# Vulnerable SSH Configuration
Port 22
Banner /etc/ssh/banner.txt
PasswordAuthentication yes
PermitRootLogin yes
PermitEmptyPasswords yes
MaxAuthTries 100
MaxSessions 10
PubkeyAuthentication yes
StrictModes no
LoginGraceTime 120
X11Forwarding yes
TCPKeepAlive yes
PermitUserEnvironment yes
Compression yes
UsePAM no
"@
    
    $sshdConfig | Out-File "C:\ProgramData\ssh\sshd_config" -Encoding ascii -Force
    
    # Create banner with flag
    "Welcome to Vulnerable SSH Server`n$sshFlag" | Out-File "C:\ProgramData\ssh\banner.txt" -Encoding ascii
    
    # Create SSH keys with flag in authorized_keys comment
    $sshKeyFlag = New-CTFFlag -Location "SSH authorized_keys" -Description "Hidden in SSH authorized_keys" -Points 30 -Difficulty "Medium" -Technique "SSH key enumeration"
    New-Item -Path "C:\ProgramData\ssh\authorized_keys" -ItemType File -Force
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 admin@vulnerable # $sshKeyFlag" | Out-File "C:\ProgramData\ssh\authorized_keys"
    
    # Restart SSH
    Restart-Service sshd
    
    # Open firewall
    New-NetFirewallRule -Name sshd -DisplayName 'SSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    
    Write-Host "  SSH server configured with flags" -ForegroundColor Green
}

# Function to configure printer with flag
function Configure-NetworkPrinter {
    param([string]$PrinterIP)
    
    Write-Host "Configuring network printer connection with flag..." -ForegroundColor Yellow
    
    # Add printer port
    Add-PrinterPort -Name "IP_$PrinterIP" -PrinterHostAddress $PrinterIP -ErrorAction SilentlyContinue
    
    # Install generic printer driver
    Add-PrinterDriver -Name "Generic / Text Only" -ErrorAction SilentlyContinue
    
    # Printer flag in comment
    $printerFlag = New-CTFFlag -Location "Printer Properties" -Description "Printer configuration" -Points 20 -Difficulty "Medium" -Technique "Printer enumeration"
    
    # Add printer with flag in comment
    Add-Printer -Name "VulnPrinter" -DriverName "Generic / Text Only" -PortName "IP_$PrinterIP" -Comment $printerFlag -Shared -ShareName "VulnPrinter" -ErrorAction SilentlyContinue
    
    # Set permissions
    $printer = Get-Printer -Name "VulnPrinter" -ErrorAction SilentlyContinue
    if ($printer) {
        Set-Printer -Name "VulnPrinter" -PermissionSDDL "O:BAG:DUD:(A;OIIO;RPWPDTSDWD;;;WD)" -ErrorAction SilentlyContinue
        Write-Host "  Printer configured with flag" -ForegroundColor Green
    }
}

# Function to create vulnerable services with flags
function Create-VulnerableServices {
    Write-Host "Creating vulnerable services with flags..." -ForegroundColor Yellow
    
    # Create a service running as SYSTEM with unquoted path
    New-Item -Path "C:\Program Files\Vulnerable Service" -ItemType Directory -Force
    
    # Service flag
    $serviceFlag = New-CTFFlag -Location "Vulnerable Service" -Description "Unquoted service path exploitation" -Points 35 -Difficulty "Medium" -Technique "Service exploitation"
    "echo $serviceFlag > C:\flag_service.txt" | Out-File "C:\Program Files\Vulnerable Service\service.bat"
    
    sc.exe create VulnService binpath= "C:\Program Files\Vulnerable Service\service.bat" start= auto
    sc.exe config VulnService obj= "LocalSystem"
    
    # Service with flag in description
    $svcDescFlag = New-CTFFlag -Location "Service Description" -Description "WeakService description" -Points 15 -Difficulty "Easy" -Technique "Service enumeration"
    sc.exe create WeakService binpath= "C:\Windows\System32\cmd.exe /c echo vulnerable" start= auto
    sc.exe description WeakService "Weak Service - $svcDescFlag"
    sc.exe sdset WeakService "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)(A;;RPWP;;;WD)"
    
    Write-Host "  Vulnerable services created with flags" -ForegroundColor Green
}

# Function to configure scheduled tasks with flags
function Create-VulnerableScheduledTasks {
    Write-Host "Creating vulnerable scheduled tasks with flags..." -ForegroundColor Yellow
    
    # Task flag
    $taskFlag = New-CTFFlag -Location "Scheduled Task" -Description "VulnTask output" -Points 25 -Difficulty "Medium" -Technique "Scheduled task abuse"
    
    # Create task with stored credentials that writes flag
    $action = New-ScheduledTaskAction -Execute "C:\Windows\System32\cmd.exe" -Argument "/c echo $taskFlag > C:\Public\taskflag.txt"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
    $principal = New-ScheduledTaskPrincipal -UserId "admin" -LogonType Password -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    
    Register-ScheduledTask -TaskName "VulnTask" -Action $action -Trigger $trigger -Settings $settings -User "admin" -Password "admin" -ErrorAction SilentlyContinue
    
    # Create task with writable path
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Backup Task - Check C:\Temp for details</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2024-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
  </Settings>
  <Actions>
    <Exec>
      <Command>C:\Temp\backup.exe</Command>
    </Exec>
  </Actions>
</Task>
"@
    
    Register-ScheduledTask -TaskName "BackupTask" -Xml $taskXml -Force -ErrorAction SilentlyContinue
    New-Item -Path "C:\Temp" -ItemType Directory -Force
    icacls "C:\Temp" /grant Everyone:F /T
    
    Write-Host "  Vulnerable scheduled tasks created with flags" -ForegroundColor Green
}

# Function to create registry flags
function Create-RegistryFlags {
    Write-Host "Creating registry-based flags..." -ForegroundColor Yellow
    
    # Easy flag in HKLM
    $regFlag1 = New-CTFFlag -Location "Registry HKLM" -Description "HKLM:\SOFTWARE\VulnApp" -Points 15 -Difficulty "Easy" -Technique "Registry enumeration"
    New-Item -Path "HKLM:\SOFTWARE\VulnApp" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\VulnApp" -Name "LicenseKey" -Value $regFlag1 -Force
    
    # Medium flag in HKCU
    $regFlag2 = New-CTFFlag -Location "Registry HKCU" -Description "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Points 25 -Difficulty "Medium" -Technique "Persistence mechanism review"
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "UpdaterFlag" -Value "cmd /c echo $regFlag2" -Force
    
    # Hard flag in service registry
    $regFlag3 = New-CTFFlag -Location "Registry Service" -Description "Service ImagePath" -Points 35 -Difficulty "Hard" -Technique "Service registry analysis"
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VulnService" -Name "Flag" -Value $regFlag3 -Force
    
    Write-Host "  Registry flags created" -ForegroundColor Green
}

# Function to create event log flags
function Create-EventLogFlags {
    Write-Host "Creating event log flags..." -ForegroundColor Yellow
    
    # Create custom event log
    New-EventLog -LogName "VulnerableLab" -Source "FlagSystem" -ErrorAction SilentlyContinue
    
    # Write flag to event log
    $eventFlag = New-CTFFlag -Location "Event Log" -Description "VulnerableLab event log" -Points 20 -Difficulty "Medium" -Technique "Event log analysis"
    Write-EventLog -LogName "VulnerableLab" -Source "FlagSystem" -EventId 1337 -Message "Security Flag: $eventFlag" -EntryType Information
    
    Write-Host "  Event log flag created" -ForegroundColor Green
}

# Function to create PowerShell history flag
function Create-PowerShellHistoryFlag {
    Write-Host "Creating PowerShell history flag..." -ForegroundColor Yellow
    
    $historyFlag = New-CTFFlag -Location "PowerShell History" -Description "PSReadline history" -Points 30 -Difficulty "Medium" -Technique "Command history analysis"
    
    # Add flag to PowerShell history for all users
    $users = Get-ChildItem C:\Users -Directory
    foreach ($user in $users) {
        $historyPath = "C:\Users\$($user.Name)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"
        New-Item -Path $historyPath -ItemType Directory -Force -ErrorAction SilentlyContinue
        "# Admin ran this command with the flag: $historyFlag" | Out-File "$historyPath\ConsoleHost_history.txt" -Append
    }
    
    Write-Host "  PowerShell history flag created" -ForegroundColor Green
}

# Function to create environment variable flag
function Create-EnvironmentFlag {
    Write-Host "Creating environment variable flag..." -ForegroundColor Yellow
    
    $envFlag = New-CTFFlag -Location "Environment Variable" -Description "System environment variable" -Points 15 -Difficulty "Easy" -Technique "Environment enumeration"
    
    [Environment]::SetEnvironmentVariable("CTF_FLAG", $envFlag, "Machine")
    [Environment]::SetEnvironmentVariable("DEBUG_KEY", "Check CTF_FLAG variable", "Machine")
    
    Write-Host "  Environment variable flag created" -ForegroundColor Green
}

# Function to create web application flags
function Create-VulnerableWebApps {
    Write-Host "Creating vulnerable web applications with flags..." -ForegroundColor Yellow
    
    # Install IIS
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole, IIS-WebServer, IIS-CommonHttpFeatures, IIS-HttpErrors, IIS-HttpRedirect, IIS-ApplicationDevelopment, IIS-HealthAndDiagnostics, IIS-HttpLogging, IIS-Security, IIS-RequestFiltering, IIS-Performance, IIS-WebServerManagementTools, IIS-ManagementConsole, IIS-IIS6ManagementCompatibility, IIS-Metabase -All -NoRestart
    
    # Create vulnerable web app
    New-Item -Path "C:\inetpub\wwwroot\vulnapp" -ItemType Directory -Force
    New-Item -Path "C:\inetpub\wwwroot\admin" -ItemType Directory -Force
    New-Item -Path "C:\inetpub\wwwroot\.git" -ItemType Directory -Force
    
    # Web flag in HTML comment
    $webFlag1 = New-CTFFlag -Location "Web HTML Comment" -Description "Login page HTML comment" -Points 10 -Difficulty "Easy" -Technique "Web source review"
    
    # Create vulnerable PHP-like file
    $vulnPage = @"
<html>
<head><title>Vulnerable App</title></head>
<body>
<h1>Admin Panel</h1>
<!-- TODO: Remove debug info before production -->
<!-- Admin password: $LabPassword -->
<!-- $webFlag1 -->
<form method="GET">
    Username: <input type="text" name="user"><br>
    Password: <input type="password" name="pass"><br>
    <input type="submit" value="Login">
</form>
</body>
</html>
"@
    $vulnPage | Out-File "C:\inetpub\wwwroot\vulnapp\login.html"
    
    # Robots.txt flag
    $robotsFlag = New-CTFFlag -Location "robots.txt" -Description "Disallowed path in robots.txt" -Points 15 -Difficulty "Easy" -Technique "Web enumeration"
    "User-agent: *`nDisallow: /admin/`nDisallow: /backup/`n# Flag: $robotsFlag" | Out-File "C:\inetpub\wwwroot\robots.txt"
    
    # Git config flag
    $gitFlag = New-CTFFlag -Location ".git/config" -Description "Git repository leak" -Points 30 -Difficulty "Medium" -Technique "Information disclosure"
    "[core]`n`trepositoryformatversion = 0`n`tflag = $gitFlag" | Out-File "C:\inetpub\wwwroot\.git\config"
    
    # web.config flag
    $configFlag = New-CTFFlag -Location "web.config" -Description "IIS configuration file" -Points 25 -Difficulty "Medium" -Technique "Configuration review"
    @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <appSettings>
        <add key="flag" value="$configFlag" />
    </appSettings>
</configuration>
"@ | Out-File "C:\inetpub\wwwroot\web.config"
    
    # Enable directory browsing
    Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $true -PSPath IIS:\Sites\Default Web Site
    
    Write-Host "  Web applications created with flags" -ForegroundColor Green
}

# Function to create database flag
function Create-DatabaseFlag {
    Write-Host "Creating database flag..." -ForegroundColor Yellow
    
    $dbFlag = New-CTFFlag -Location "SQLite Database" -Description "Local database file" -Points 35 -Difficulty "Hard" -Technique "Database extraction"
    
    # Create a simple SQLite database file (simulated)
    $dbPath = "C:\Data\vulnapp.db"
    @"
SQLite format 3
Table: flags
id|flag|points
1|$dbFlag|35
"@ | Out-File $dbPath -Encoding UTF8
    
    Write-Host "  Database flag created" -ForegroundColor Green
}

# Function to create process/memory flag
function Create-ProcessFlag {
    Write-Host "Creating process-based flag..." -ForegroundColor Yellow
    
    $processFlag = New-CTFFlag -Location "Running Process" -Description "FlagKeeper.exe process memory" -Points 40 -Difficulty "Hard" -Technique "Memory analysis"
    
    # Create a simple executable that holds the flag in memory
    $processScript = @"
`$flag = "$processFlag"
while (`$true) {
    Start-Sleep -Seconds 60
    # Flag is in memory: `$flag
}
"@
    
    $processScript | Out-File "C:\Windows\Temp\FlagKeeper.ps1"
    
    # Start the process
    Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -File C:\Windows\Temp\FlagKeeper.ps1" -PassThru | Out-Null
    
    Write-Host "  Process flag created" -ForegroundColor Green
}

# Function to generate flag documentation
function Generate-FlagReport {
    Write-Host "`nGenerating flag report..." -ForegroundColor Cyan
    
    $reportPath = "C:\CTF_FLAGS_REPORT_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>CTF Flag Report - $(hostname)</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #f0f0f0; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }
        h1 { color: #333; border-bottom: 3px solid #007acc; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #007acc; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .easy { color: green; font-weight: bold; }
        .medium { color: orange; font-weight: bold; }
        .hard { color: red; font-weight: bold; }
        .stats { background: #e7f4ff; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .flag-code { font-family: 'Courier New'; background: #f0f0f0; padding: 2px 5px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CTF Flag Report - $(hostname)</h1>
        <div class="stats">
            <h2>Statistics</h2>
            <p><strong>Total Flags:</strong> $($global:FlagList.Count)</p>
            <p><strong>Total Points:</strong> $(($global:FlagList | Measure-Object -Property Points -Sum).Sum)</p>
            <p><strong>Easy Flags:</strong> $(($global:FlagList | Where-Object {$_.Difficulty -eq 'Easy'}).Count)</p>
            <p><strong>Medium Flags:</strong> $(($global:FlagList | Where-Object {$_.Difficulty -eq 'Medium'}).Count)</p>
            <p><strong>Hard Flags:</strong> $(($global:FlagList | Where-Object {$_.Difficulty -eq 'Hard'}).Count)</p>
            <p><strong>Report Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
        
        <h2>Flag Details</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Flag</th>
                    <th>Location</th>
                    <th>Description</th>
                    <th>Points</th>
                    <th>Difficulty</th>
                    <th>Technique</th>
                </tr>
            </thead>
            <tbody>
"@
    
    foreach ($flag in $global:FlagList | Sort-Object FlagID) {
        $difficultyClass = $flag.Difficulty.ToLower()
        $html += @"
                <tr>
                    <td>$($flag.FlagID)</td>
                    <td class="flag-code">$($flag.Flag)</td>
                    <td>$($flag.Location)</td>
                    <td>$($flag.Description)</td>
                    <td>$($flag.Points)</td>
                    <td class="$difficultyClass">$($flag.Difficulty)</td>
                    <td>$($flag.Technique)</td>
                </tr>
"@
    }
    
    $html += @"
            </tbody>
        </table>
        
        <h2>Hints for Students</h2>
        <ul>
            <li><strong>Easy (10-15 points):</strong> Basic enumeration, service discovery, file searching</li>
            <li><strong>Medium (20-30 points):</strong> Exploitation, credential access, privilege escalation</li>
            <li><strong>Hard (35-40 points):</strong> Advanced techniques, memory analysis, complex exploitation</li>
        </ul>
        
        <h2>Recommended Tools</h2>
        <ul>
            <li>Enumeration: nmap, enum4linux, smbclient, gobuster</li>
            <li>Exploitation: Metasploit, Impacket, Evil-WinRM</li>
            <li>Post-Exploitation: Mimikatz, PowerView, BloodHound</li>
            <li>Analysis: strings, file, PowerShell, Process Explorer</li>
        </ul>
    </div>
</body>
</html>
"@
    
    $html | Out-File $reportPath -Encoding UTF8
    
    # Also create a CSV for easier parsing
    $csvPath = $reportPath -replace '\.html$', '.csv'
    $global:FlagList | Export-Csv -Path $csvPath -NoTypeInformation
    
    Write-Host "  Flag report saved to: $reportPath" -ForegroundColor Green
    Write-Host "  CSV report saved to: $csvPath" -ForegroundColor Green
    
    return $reportPath
}

# Main execution
Write-Host "`nStarting vulnerable server configuration with CTF flags..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Run all configurations
Create-WeakUsers
Disable-SecurityFeatures
Configure-VulnerableRDP
Configure-VulnerableSMB
Configure-VulnerableFTP
Configure-VulnerableSSH
Configure-NetworkPrinter -PrinterIP $NetworkPrinter
Create-VulnerableServices
Create-VulnerableScheduledTasks
Create-RegistryFlags
Create-EventLogFlags
Create-PowerShellHistoryFlag
Create-EnvironmentFlag
Create-VulnerableWebApps
Create-DatabaseFlag
Create-ProcessFlag
Enable-LegacyProtocols

# Additional misconfigurations
Write-Host "`nApplying additional misconfigurations..." -ForegroundColor Yellow

# AutoLogon
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -Value "admin"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -Value "admin"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value 1

# Store credentials
cmdkey /add:DC01 /user:Administrator /pass:$LabPassword
cmdkey /add:FileServer /user:admin /pass:admin

# Enable PowerShell remoting without authentication
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true

# Generate reports if requested
if ($GenerateFlagReport) {
    $reportPath = Generate-FlagReport
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Server vulnerability and CTF flag configuration complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "CTF FLAG STATISTICS:" -ForegroundColor Cyan
Write-Host "  Total Flags Placed: $($global:FlagList.Count)" -ForegroundColor Yellow
Write-Host "  Total Points Available: $(($global:FlagList | Measure-Object -Property Points -Sum).Sum)" -ForegroundColor Yellow
Write-Host "  Difficulty Distribution:" -ForegroundColor Yellow
Write-Host "    Easy: $(($global:FlagList | Where-Object {$_.Difficulty -eq 'Easy'}).Count) flags" -ForegroundColor Green
Write-Host "    Medium: $(($global:FlagList | Where-Object {$_.Difficulty -eq 'Medium'}).Count) flags" -ForegroundColor DarkYellow
Write-Host "    Hard: $(($global:FlagList | Where-Object {$_.Difficulty -eq 'Hard'}).Count) flags" -ForegroundColor Red
Write-Host ""
Write-Host "Flag Format: FLAG{$TeamIdentifier-SRV-XXX}" -ForegroundColor Cyan
Write-Host ""
if ($GenerateFlagReport) {
    Write-Host "Flag report generated at: $reportPath" -ForegroundColor Green
    Write-Host "Open the HTML report for full flag details and hints!" -ForegroundColor Green
} else {
    Write-Host "To generate a detailed flag report, run with -GenerateFlagReport switch" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "Vulnerable users created:" -ForegroundColor Cyan
Write-Host "  Administrator: $LabPassword" -ForegroundColor Yellow
Write-Host "  admin: admin" -ForegroundColor Yellow
Write-Host "  user1: password" -ForegroundColor Yellow
Write-Host "  backup: backup123" -ForegroundColor Yellow
Write-Host "  ftpuser: ftp123" -ForegroundColor Yellow
Write-Host ""
Write-Host "Services configured:" -ForegroundColor Cyan
Write-Host "  - RDP (3389) - No NLA, allows blank passwords" -ForegroundColor Yellow
Write-Host "  - SMB (445) - SMBv1 enabled, null sessions" -ForegroundColor Yellow
Write-Host "  - FTP (21) - Anonymous access, weak credentials" -ForegroundColor Yellow
Write-Host "  - SSH (22) - Permits root, empty passwords" -ForegroundColor Yellow
Write-Host "  - HTTP (80) - Directory browsing, debug info" -ForegroundColor Yellow
Write-Host ""
Write-Host "REMINDER: This server is now EXTREMELY VULNERABLE!" -ForegroundColor Red
Write-Host "Only use in isolated lab environments!" -ForegroundColor Red
Write-Host ""
Write-Host "Please restart the server to ensure all changes take effect." -ForegroundColor Cyan
