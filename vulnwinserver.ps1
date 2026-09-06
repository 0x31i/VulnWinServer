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
    [switch]$UpgradeOpenSSH,

    # Skip the interactive "type VULNERABLE" confirmation so the script can build
    # unattended (scheduled task / remote build). Use only in an isolated lab.
    [switch]$Unattended,

    # OPTIONAL: join the OVERCLOCK.LOCAL domain (VM1 / Domain Controller). Additive --
    # every lab account created above is a LOCAL account, so joining does not affect any
    # existing flag. DCIP default = production DC 192.168.148.10; for a local Proxmox build pass -DCIP 192.168.1.108.
    [switch]$JoinDomain,
    [string]$DomainName     = "OVERCLOCK.LOCAL",
    [string]$DCIP           = "192.168.148.10",
    [string]$DomainJoinUser = "OVERCLOCK\svc_join",
    [string]$DomainJoinPass = "J0in-Comp-2026!"
)

Write-Host "==========================================" -ForegroundColor Red
Write-Host "VULNERABLE LAB CONFIGURATION SCRIPT v5" -ForegroundColor Red
Write-Host "FOR EDUCATIONAL PURPOSES ONLY" -ForegroundColor Red
Write-Host "NEVER USE IN PRODUCTION ENVIRONMENTS" -ForegroundColor Red
Write-Host "==========================================" -ForegroundColor Red
Write-Host ""
if (-not $Unattended) {
    $confirm = Read-Host "Type 'VULNERABLE' to confirm this is for an isolated lab"
    if ($confirm -ne "VULNERABLE") { exit }
}

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

# ---------------------------------------------------------------------------
# FLAG SEED — the single source of truth for every flag on this box.
#   * Change this ONE value to ROTATE all flags (they regenerate deterministically).
#   * Keep it IDENTICAL across the three lab build scripts (win10 / server / OCWA).
#   * This build script NEVER emits the plaintext answers. Generate the instructor
#     answer key OFF-box with Generate-AnswerKey.py (admin-only, NOT distributed).
# Values are derived (below), so NO "FLAG{...}" or digit string is stored here ->
# a student running `Select-String 'FLAG{'` finds nothing.
# ---------------------------------------------------------------------------
$global:OC_FLAG_SEED = $env:OC_FLAG_SEED
if ([string]::IsNullOrWhiteSpace($global:OC_FLAG_SEED)) {
    # No seed supplied: generate a random one so a home lab "just works".
    # The OFFICIAL graded box is built by exporting the secret course seed first.
    $__b = New-Object 'System.Byte[]' 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($__b)
    $global:OC_FLAG_SEED = -join ($__b | ForEach-Object { $_.ToString('x2') })
    Write-Host "[i] No OC_FLAG_SEED set -- generated a random lab seed:" -ForegroundColor Yellow
    Write-Host "      $global:OC_FLAG_SEED" -ForegroundColor Yellow
    Write-Host "      Save it if you want to regenerate your own answer key later." -ForegroundColor Yellow
}

# Deterministic keyed flag body: FLAG{ codename + 8 digits }, both derived from
# HMAC-SHA256(seed, key). Keyed by a STABLE name (the flag's -Location string), so
# adding/reordering flags never disturbs the others. Same math as Generate-AnswerKey.py.
function Get-OCFlagBody {
    param([string]$Key)
    $nk = "server::" + $Key   # namespace by box so each box's flag set is independent
    # CODENAME from a FIXED salt -> PERMANENT (survives seed rotation; a stable flag identifier for the
    # instructor writeups). DIGITS from $OC_FLAG_SEED -> only these rotate. Matches Generate-AnswerKey.py.
    $ch = New-Object System.Security.Cryptography.HMACSHA256
    $ch.Key = [System.Text.Encoding]::UTF8.GetBytes("oc-codename-v1")
    $chex = (($ch.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($nk))) | ForEach-Object { $_.ToString('x2') }) -join ''
    $idx  = [Convert]::ToUInt32($chex.Substring(0,8),16) % $PokemonList.Count
    $dh = New-Object System.Security.Cryptography.HMACSHA256
    $dh.Key = [System.Text.Encoding]::UTF8.GetBytes($global:OC_FLAG_SEED)
    $dhex = (($dh.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($nk))) | ForEach-Object { $_.ToString('x2') }) -join ''
    $digits = [Convert]::ToUInt32($dhex.Substring(8,8),16) % 100000000
    return "$($PokemonList[$idx])" + ("{0:D8}" -f $digits)
}

# Generate a deterministic flag KEYED BY -Location (stable name, not call order).
function New-CTFFlag {
    param(
        [string]$Location,
        [string]$Description,
        [int]$Points,
        [string]$Difficulty,
        [string]$Technique
    )

    $flag = "FLAG{" + (Get-OCFlagBody $Location) + "}"

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

# Grep-proof helper: base64 a flag so `Select-String FLAG{` / grep finds nothing
# in the registry or on disk. The student recognizes + decodes it (a real skill).
function Enc-Flag { param([string]$f) return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($f)) }

# Function to create weak users with embedded flags
function Create-WeakUsers {
    Write-Host "Creating vulnerable user accounts with flags..." -ForegroundColor Yellow
    
    # User with flag in description
    $flag1 = New-CTFFlag -Location "User Description" -Description "Hidden in user description" -Points 10 -Difficulty "Easy" -Technique "User enumeration"
    
    $users = @(
        # overclock is the STUDENT'S low-priv foothold (auto-logon user). It must NOT be an admin -- the
        # whole box is a privilege-escalation lab and every exploit flag is ACL'd to SYSTEM+Administrators,
        # so an admin overclock could read them all without exploiting. "Remote Management Users" lets the
        # student reach it over WinRM/evil-winrm as a standard user; escalation earns admin/SYSTEM.
        @{Name="overclock"; Password="Administrator2025!"; Groups=@("Users","Remote Management Users"); Description=$flag1},
        @{Name="user1"; Password="Password123!"; Groups=@("Users"); Description="Standard User"},
        # localadmin shared with the Win10 workstation (Administrator123) so a looted
        # workstation localadmin cred/hash pivots here via PtH/reuse (documented lateral path).
        @{Name="localadmin"; Password="Administrator123"; Groups=@("Administrators"); Description="Local Administrator"},
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
    
    # Create a user whose NAME is a short flag (Windows 20-char username limit).
    # Seed-derived + keyed (matches Generate-AnswerKey.py's special case for "Username"):
    #   short codename + 4 digits, both from HMAC(seed, "server::username-flag").
    $shortPokemon = @("PIKA", "MEW", "CHAR", "BULB", "SQUIR", "EEVEE", "DRAGO", "GENGAR")
    # short codename from FIXED salt (permanent), 4 digits from seed (rotate). Matches Generate-AnswerKey.py.
    $ucn = New-Object System.Security.Cryptography.HMACSHA256
    $ucn.Key = [System.Text.Encoding]::UTF8.GetBytes("oc-codename-v1")
    $ucnHex = (($ucn.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("server::username-flag"))) | ForEach-Object { $_.ToString('x2') }) -join ''
    $selectedPokemon = $shortPokemon[[Convert]::ToUInt32($ucnHex.Substring(0,8),16) % $shortPokemon.Count]
    $udg = New-Object System.Security.Cryptography.HMACSHA256
    $udg.Key = [System.Text.Encoding]::UTF8.GetBytes($global:OC_FLAG_SEED)
    $udgHex = (($udg.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("server::username-flag"))) | ForEach-Object { $_.ToString('x2') }) -join ''
    $uDigits = "{0:D4}" -f ([Convert]::ToUInt32($udgHex.Substring(8,4),16) % 10000)
    $flagUserShort = "FLAG{$selectedPokemon$uDigits}"  # e.g., FLAG{PIKA1234} <= 20 chars
    
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
    
    # TWO-PART FLAGS (exploit-weighted):
    #  Part 1 (identify, Medium): WDigest UseLogonCredential=1 + RunAsPPL=0 is discoverable via config enum.
    $lsaFind = New-CTFFlag -Location "LSASS misconfig (identify)" -Description "WDigest cleartext + LSA Protection off" -Points 15 -Difficulty "Medium" -Technique "Config enumeration"
    if (-not (Test-Path "HKLM:\SOFTWARE\OCLab")) { New-Item -Path "HKLM:\SOFTWARE\OCLab" -Force -ErrorAction SilentlyContinue | Out-Null }  # guard: -Force on an existing key WIPES its values (clobbered the identify notes)
    New-ItemProperty -Path "HKLM:\SOFTWARE\OCLab" -Name "WDigestNote" -Value (Enc-Flag $lsaFind) -Force -ErrorAction SilentlyContinue | Out-Null

    #  Part 2 (exploit, Hard): AIRTIGHT live-cred artifact. svc_backup runs as a RESIDENT WINDOWS SERVICE,
    #  so with WDigest on its CLEARTEXT password sits in LSASS (service logon type-5 IS WDigest-cached).
    #  mimikatz sekurlsa / lsassy recovers it -> the password IS the flag. ONLY an LSASS dump surfaces it
    #  (no file/reg shortcut). A real compiled service is required: a fake `ping` service gets killed on the
    #  SCM start-timeout and its logon session ends; a real ServiceBase stays resident.
    $mimikatzFlag = New-CTFFlag -Location "LSASS Memory (exploit)" -Description "Cleartext service cred recovered from LSASS" -Points 45 -Difficulty "Hard" -Technique "Mimikatz sekurlsa credential dump"
    $svcAcct = "svc_backup"
    $svcPwd  = (Enc-Flag $mimikatzFlag)                 # base64 token used AS the password -> lands in LSASS
    $global:OCSvcAcct = $svcAcct; $global:OCSvcPwd = $svcPwd   # for the end-of-build LSASS service finalizer
    $secPw   = ConvertTo-SecureString $svcPwd -AsPlainText -Force
    New-LocalUser -Name $svcAcct -Password $secPw -PasswordNeverExpires -AccountNeverExpires -ErrorAction SilentlyContinue | Out-Null
    Add-LocalGroupMember -Group 'Users' -Member $svcAcct -ErrorAction SilentlyContinue | Out-Null
    # Grant "Log on as a service" -- sc.exe create does NOT auto-grant it (start fails 1069 otherwise).
    $svcSid = (Get-LocalUser $svcAcct).SID.Value
    $seInf  = "C:\Windows\Temp\se_svc.inf"
    secedit /export /cfg $seInf /areas USER_RIGHTS | Out-Null
    $seTxt = Get-Content $seInf
    if ($seTxt -match '^SeServiceLogonRight') {
        $seTxt = $seTxt -replace '^(SeServiceLogonRight\s*=\s*.*)$', ('$1,*' + $svcSid)
    } else {
        $seTxt = $seTxt -replace '(\[Privilege Rights\])', ('$1' + "`r`nSeServiceLogonRight = *" + $svcSid)
    }
    $seTxt | Set-Content $seInf -Force
    secedit /configure /db "C:\Windows\Temp\se_svc.sdb" /cfg $seInf /areas USER_RIGHTS | Out-Null
    $svcSrc = @'
using System.ServiceProcess;
public class OCBackupSvc : ServiceBase {
  public OCBackupSvc(){ this.ServiceName = "OCLabBackup"; }
  protected override void OnStart(string[] args){}
  protected override void OnStop(){}
  public static void Main(){ ServiceBase.Run(new OCBackupSvc()); }
}
'@
    $svcCs = "C:\Windows\Temp\ocbackupsvc.cs"; $svcExe = "C:\Windows\OCLabBackup.exe"
    $svcSrc | Out-File $svcCs -Encoding ascii -Force
    $csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    if (!(Test-Path $csc)) { $csc = "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe" }
    & $csc /nologo /target:exe /out:$svcExe /r:System.ServiceProcess.dll $svcCs 2>$null | Out-Null
    if (Test-Path $svcExe) {
        sc.exe create OCLabBackup binPath= "$svcExe" obj= ".\$svcAcct" password= "$svcPwd" start= auto DisplayName= "OC Backup Agent" | Out-Null
        sc.exe start OCLabBackup | Out-Null
    }
    
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
    
    # TWO-PART (exploit-weighted):
    #  Part 1 (identify, Medium): SeDebugPrivilege held by non-admins is discoverable (whoami /priv, secpol).
    $seFind = New-CTFFlag -Location "SeDebug (identify)" -Description "SeDebugPrivilege held by non-admins" -Points 15 -Difficulty "Medium" -Technique "Privilege enumeration"
    if (-not (Test-Path "HKLM:\SOFTWARE\OCLab")) { New-Item -Path "HKLM:\SOFTWARE\OCLab" -Force -ErrorAction SilentlyContinue | Out-Null }  # guard: -Force on an existing key WIPES its values (clobbered the identify notes)
    New-ItemProperty -Path "HKLM:\SOFTWARE\OCLab" -Name "SeDebugNote" -Value (Enc-Flag $seFind) -Force -ErrorAction SilentlyContinue | Out-Null
    #  Part 2 (exploit, Hard): SYSTEM-only. Abuse SeDebug to steal a SYSTEM process token, become SYSTEM, read this.
    $debugFlag = New-CTFFlag -Location "SeDebug (exploit)" -Description "SYSTEM token stolen via SeDebug" -Points 40 -Difficulty "Hard" -Technique "SeDebugPrivilege token theft -> SYSTEM"
    $seDebugFlagPath = "C:\Windows\System32\config\systemprofile\sedebug_flag.txt"
    if (!(Test-Path (Split-Path $seDebugFlagPath))) { New-Item -Path (Split-Path $seDebugFlagPath) -ItemType Directory -Force | Out-Null }
    (Enc-Flag $debugFlag) | Out-File $seDebugFlagPath -Force
    icacls $seDebugFlagPath /inheritance:r /grant "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null
    
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
    
    # TWO-PART (exploit-weighted):
    #  Part 1 (identify, Medium): NTLM/PtH config (RestrictedAdmin off, LmCompatibilityLevel low) is discoverable.
    $pthFind = New-CTFFlag -Location "Pass-the-Hash (identify)" -Description "NTLM/PtH configuration spotted" -Points 15 -Difficulty "Medium" -Technique "Config enumeration"
    if (-not (Test-Path "HKLM:\SOFTWARE\OCLab")) { New-Item -Path "HKLM:\SOFTWARE\OCLab" -Force -ErrorAction SilentlyContinue | Out-Null }  # guard: -Force on an existing key WIPES its values (clobbered the identify notes)
    New-ItemProperty -Path "HKLM:\SOFTWARE\OCLab" -Name "PthNote" -Value (Enc-Flag $pthFind) -Force -ErrorAction SilentlyContinue | Out-Null
    #  Part 2 (exploit, Hard): dump a local admin NT hash and PASS THE HASH; the flag is SYSTEM/admin-only.
    $pthFlag = New-CTFFlag -Location "Pass-the-Hash (exploit)" -Description "Authenticated via passed hash" -Points 50 -Difficulty "Hard" -Technique "Pass-the-Hash -> admin"
    $pthPath = "C:\Windows\System32\config\systemprofile\pth_success.txt"
    New-Item -Path (Split-Path $pthPath -Parent) -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    (Enc-Flag $pthFlag) | Out-File $pthPath -Force
    icacls $pthPath /inheritance:r /grant "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null
    
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
    
    # UAC MUST stay ENABLED (EnableLUA=1). AlwaysInstallElevated (FLAG 16) only works with UAC on:
    # with UAC off, every process (even a standard user's) runs at HIGH integrity, msiexec is treated as
    # already-elevated, and a non-admin per-machine install is rejected (error 1625). Real AIE-vulnerable
    # boxes have UAC on -- AIE is the misconfiguration -- so this is both correct and more realistic.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1
    # ...but keep remote local-admin logons UNFILTERED so nxc/evil-winrm/psexec and Pass-the-Hash (FLAG 5)
    # still get a full admin token over the network (otherwise UAC hands them a filtered medium-IL token).
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 1 -ErrorAction SilentlyContinue
    
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
    New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "CertificateComment" -Value (Enc-Flag $rdpFlag) -Force
    
    Write-Host "  RDP configured with vulnerabilities and flag" -ForegroundColor Green
}

# Function to configure vulnerable SMB shares with flags
function Configure-VulnerableSMB {
    Write-Host "Configuring vulnerable SMB shares with flags..." -ForegroundColor Yellow
    
    # Enable SMBv1
    Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -All -NoRestart -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Value 1
    
    # Create vulnerable shares with flags
    # Tier controls who can READ each share, so the SMB flags form a real anon -> user -> admin progression:
    #   Anon  = readable with a null session (smbclient -N); the anon-enum settings below keep this working.
    #   Auth  = any authenticated user (denies anonymous AND Guest); the recovered user1 cred unlocks it.
    #   Admin = Administrators only; you must escalate (e.g. PtH/LSASS) before you can read it.
    $shares = @(
        @{Name="Public"; Path="C:\Public"; FlagFile=$true; FlagDifficulty="Easy"; Points=10; Tier="Anon"},
        @{Name="Data"; Path="C:\Data"; FlagFile=$false; Tier="Anon"},
        @{Name="Backup"; Path="C:\Backup"; FlagFile=$true; FlagDifficulty="Medium"; Points=20; Tier="Auth"},
        @{Name="IT"; Path="C:\IT"; FlagFile=$true; FlagDifficulty="Hard"; Points=30; Tier="Admin"},
        @{Name="Finance"; Path="C:\Finance"; FlagFile=$false; Tier="Anon"}
    )
    
    foreach ($share in $shares) {
        New-Item -Path $share.Path -ItemType Directory -Force -ErrorAction SilentlyContinue
        New-SmbShare -Name $share.Name -Path $share.Path -FullAccess "Everyone" -ErrorAction SilentlyContinue

        # Enforce the read tier at the SHARE level (share ACL is the intersection floor, so it denies
        # anonymous even though NTFS below stays open and EveryoneIncludesAnonymous is on for RID cycling).
        switch ($share.Tier) {
            "Auth" {
                Revoke-SmbShareAccess -Name $share.Name -AccountName "Everyone" -Force -ErrorAction SilentlyContinue | Out-Null
                Grant-SmbShareAccess  -Name $share.Name -AccountName "Authenticated Users" -AccessRight Read -Force -ErrorAction SilentlyContinue | Out-Null
            }
            "Admin" {
                Revoke-SmbShareAccess -Name $share.Name -AccountName "Everyone" -Force -ErrorAction SilentlyContinue | Out-Null
                Grant-SmbShareAccess  -Name $share.Name -AccountName "BUILTIN\Administrators" -AccessRight Read -Force -ErrorAction SilentlyContinue | Out-Null
            }
            # "Anon" (default): leave FullAccess Everyone so a null session can read it.
        }

        # Set NTFS permissions
        $acl = Get-Acl $share.Path
        $permission = "Everyone","FullControl","ContainerInherit,ObjectInherit","None","Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule)
        Set-Acl $share.Path $acl
        
        # Place flags in some shares
        if ($share.FlagFile) {
            $flag = New-CTFFlag -Location "SMB Share: $($share.Name)" -Description "Found in $($share.Name) share" -Points $share.Points -Difficulty $share.FlagDifficulty -Technique "SMB enumeration"
            # realistic doc + base64 "access token" instead of a plaintext flag.txt
            "OC $($share.Name) share - internal use only.`r`nLegacy access token: $(Enc-Flag $flag)" | Out-File "$($share.Path)\README_ACCESS.txt" -Encoding ASCII -Force
        }
        
        Write-Host "  Created share: $($share.Name)" -ForegroundColor Green
    }
    
    # Plant sensitive files with embedded flags
    $passFlag = New-CTFFlag -Location "Password file" -Description "Embedded in passwords.txt" -Points 15 -Difficulty "Easy" -Technique "File search"
    "# credential backup (rotate quarterly!)`r`nAdministrator:$LabPassword`r`nsvc_token:$(Enc-Flag $passFlag)" | Out-File "C:\Public\passwords.txt" -Encoding ASCII
    
    # SAM database extraction -- TWO-PART (exploit-weighted):
    #  Part 1 (identify, Medium): a readable note reveals a SAM/SYSTEM hive backup exists here (recon).
    $samFind = New-CTFFlag -Location "SAM Backup (identify)" -Description "Spotted SAM backup location" -Points 15 -Difficulty "Medium" -Technique "File / backup enumeration"
    "SAM/SYSTEM hive backups are archived in this folder for DR.`nidentify token (base64): $(Enc-Flag $samFind)" | Out-File "C:\Backup\README.txt" -Force
    #  Part 2 (exploit, Hard): the recovered secret, gated to Administrators/SYSTEM. You reach it by
    #  actually dumping the SAM and cracking / pass-the-hashing a local admin hash, not by reading a note.
    $samFlag = New-CTFFlag -Location "SAM Backup (exploit)" -Description "Recovered from SAM dump" -Points 45 -Difficulty "Hard" -Technique "SAM database extraction"
    @"
SAM Database Backup (for Mimikatz practice)
Created: $(Get-Date)
Recovered secret (offline crack, base64): $(Enc-Flag $samFlag)
Use: mimikatz # lsadump::sam /system:system.hiv /sam:sam.hiv
"@ | Out-File "C:\Backup\sam_backup_info.txt"
    icacls "C:\Backup\sam_backup_info.txt" /inheritance:r /grant "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null
    
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

        # Part 1 (identify, Easy): readable note rewards SPOTTING the unquoted path + writable base dir
        # (enumeration with `sc qc`, PowerUp, winPEAS). Part 2 above stays SYSTEM-only (must exploit).
        $findFlag = New-CTFFlag -Location "$Name (identify)" -Description "Spotted unquoted path + writable base dir: $Name" -Points 10 -Difficulty "Easy" -Technique "Unquoted-path enumeration"
        "Service $Name : unquoted binPath + user-writable base directory (misconfigured).`nidentify token (base64): $(Enc-Flag $findFlag)" | Out-File (Join-Path $BaseDir "service_info.txt") -Force

        # Register the service with an UNQUOTED .exe binPath (no legit exe present).
        sc.exe create "$Name" binPath= "$BinPath" start= auto DisplayName= "$DisplayName" | Out-Null
        sc.exe config "$Name" obj= "LocalSystem" | Out-Null
        sc.exe description "$Name" "$Description" | Out-Null
        # Grant BUILTIN\Users (BU) SERVICE_START + query so a low-priv student can TRIGGER the hijack
        # (start the service) without needing a reboot -- standard users can't reboot a server, and the
        # legit exe is absent so the service never auto-starts on its own. This grants START/query ONLY,
        # NOT change-config (DC) -- that is the separate Modifiable-Service flag. The vulnerability here
        # remains the unquoted path + user-writable base directory.
        sc.exe sdset "$Name" "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLORC;;;BU)" | Out-Null
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
        # Guarantee MSI installs aren't blocked by a DisableMsi policy (DisableMsi=1 would
        # reject every non-managed install with error 1625, defeating the AIE exploit).
        New-ItemProperty -Path "HKLM:\$relPath" -Name "DisableMsi" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null

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

        # Seed the DEFAULT profile TEMPLATE so accounts whose profile doesn't exist yet -- notably the
        # auto-logon foothold 'overclock', whose profile Windows creates (by copying C:\Users\Default) at
        # first logon AFTER this build -- inherit HKCU AlwaysInstallElevated=1. NOTE: HKU\.DEFAULT stamped
        # above is the logon-screen/SYSTEM fallback hive, NOT the new-profile template -- a different key.
        # A standard user can't create the ACL-protected HKCU\...\Policies key himself, so this must be
        # seeded now (as SYSTEM) or the msiexec privesc silently fails for overclock.
        $defDat = "C:\Users\Default\NTUSER.DAT"
        if (Test-Path $defDat) {
            reg load "HKU\OCDEF" $defDat 2>$null | Out-Null
            Set-AIE "HKU:\OCDEF\$relPath"
            [gc]::Collect(); Start-Sleep -Milliseconds 300; reg unload "HKU\OCDEF" 2>$null | Out-Null
        }

        Write-Host "  AlwaysInstallElevated enabled (HKLM + all user hives + Default template)" -ForegroundColor Green
    } catch {
        Write-Host "  Warning: Could not fully configure AlwaysInstallElevated: $_" -ForegroundColor Yellow
    }
    
    # TWO-PART (exploit-weighted):
    #  Part 2 (exploit, Hard): SYSTEM-only flag -- only a malicious MSI running as SYSTEM reads it.
    $msiFlag = New-CTFFlag -Location "AlwaysInstallElevated (exploit)" -Description "MSI executed as SYSTEM" -Points 40 -Difficulty "Hard" -Technique "AlwaysInstallElevated MSI -> SYSTEM"
    $flagPath = "C:\Windows\System32\config\systemprofile\msi_flag.txt"
    $flagDir = Split-Path $flagPath -Parent
    if (!(Test-Path $flagDir)) { New-Item -Path $flagDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null }
    (Enc-Flag $msiFlag) | Out-File $flagPath -Force
    icacls $flagPath /inheritance:r /grant "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null

    #  Part 1 (identify, Medium): AIE enabled is discoverable in the registry; readable hint carries the token.
    $aieFind = New-CTFFlag -Location "AlwaysInstallElevated (identify)" -Description "Spotted AIE enabled (HKLM+HKCU)" -Points 15 -Difficulty "Medium" -Technique "Registry enumeration / PowerUp"
    @"
AlwaysInstallElevated is enabled (HKLM + HKCU). Any .msi installs as SYSTEM.
Generate a malicious MSI (msfvenom -f msi ...) and run it: msiexec /quiet /qn /i malicious.msi
identify token (base64): $(Enc-Flag $aieFind)
"@ | Out-File "C:\Public\msi_hint.txt" -Force
    
    Write-Host "  AlwaysInstallElevated configured with flag" -ForegroundColor Green
}

# Function to configure a modifiable-service (weak service DACL) privilege escalation.
# REPLACES the old PrintNightmare/Point-and-Print setup: on patched Server 2019 builds the
# CVE-2021-34527 path (RpcAddPrinterDriverEx / point-and-print) is dead, so this swaps in a
# reliable, extremely common real-world server privesc instead.
#
# The vulnerability: a service that runs as LocalSystem is given a WEAK OBJECT DACL granting
# BUILTIN\Users (S-1-5-32-545) SERVICE_CHANGE_CONFIG (DC) plus SERVICE_START (RP) / SERVICE_STOP (WP).
# A non-admin can therefore rewrite the service's binPath to an arbitrary command and (re)start it;
# the SCM launches that command as LocalSystem -> SYSTEM. This is what accesschk / PowerUp
# Get-ModifiableService flag on real engagements.
#
# Note this is a DIFFERENT primitive from WeakPermService (Create-VulnerableServices): that service
# grants low-priv principals only read/query rights (no DC) -> it is enumeration-only. Here Users
# hold DC, so the service is actually reconfigurable = exploitable to SYSTEM.
function Configure-ModifiableService {
    Write-Host "Configuring modifiable-service (weak service DACL) vulnerability with flags..." -ForegroundColor Yellow

    $svcName    = "SiteHealthSvc"
    $svcDisplay = "Endpoint Health Monitor"

    # Create the service (runs as LocalSystem by default). Demand-start with a benign placeholder
    # binPath so it doesn't spam boot-time SCM errors; the student supplies the real payload.
    sc.exe create $svcName binPath= "C:\Windows\System32\cmd.exe /c exit" start= demand DisplayName= "$svcDisplay" | Out-Null
    sc.exe description $svcName "Endpoint health/telemetry agent (vendor: OverClock Systems)." | Out-Null

    # THE VULNERABILITY: weak object DACL. BUILTIN\Users (BU = S-1-5-32-545) get
    # CCDCLCSWRPWPDTLOCRRC = query config / CHANGE CONFIG (DC) / query status / enum / START (RP) /
    # STOP (WP) / pause / interrogate / user-control / read. DC lets a non-admin rewrite binPath;
    # RP/WP let them restart it -> the new binPath runs as SYSTEM. (SYSTEM + Administrators keep full.)
    sc.exe sdset $svcName "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRRC;;;BU)" | Out-Null

    if ((sc.exe sdshow $svcName 2>$null) -match "CCDCLCSWRPWPDTLOCRRC;;;BU") {
        Write-Host "  Weak DACL applied to $svcName (BUILTIN\Users: SERVICE_CHANGE_CONFIG)" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: weak DACL did NOT apply to $svcName - re-run elevated" -ForegroundColor Red
    }

    # Part 1 (identify, Medium): the weak DACL is discoverable (accesschk -uwcqv <user> *,
    # PowerUp Get-ModifiableService, or `sc sdshow`). Token stored in an OCLab note + a readable breadcrumb.
    $msFind = New-CTFFlag -Location "Modifiable Service (identify)" -Description "Spotted service with user-writable DACL (SERVICE_CHANGE_CONFIG)" -Points 15 -Difficulty "Medium" -Technique "Weak service DACL enumeration"
    if (-not (Test-Path "HKLM:\SOFTWARE\OCLab")) { New-Item -Path "HKLM:\SOFTWARE\OCLab" -Force -ErrorAction SilentlyContinue | Out-Null }  # guard: -Force on an existing key WIPES its values (clobbers the other identify notes)
    New-ItemProperty -Path "HKLM:\SOFTWARE\OCLab" -Name "ModSvcNote" -Value (Enc-Flag $msFind) -Force -ErrorAction SilentlyContinue | Out-Null
    "Service '$svcName' ($svcDisplay) has a weak DACL: BUILTIN\Users hold SERVICE_CHANGE_CONFIG + START/STOP.`nA non-admin can rewrite its binPath and restart it to run code as LocalSystem.`nidentify token (base64): $(Enc-Flag $msFind)" | Out-File "C:\Public\service_permissions.txt" -Force

    # Part 2 (exploit, Hard): SYSTEM-gated. The student MUST reconfigure the service binPath + restart it
    # (which runs as SYSTEM) to read this. No world-readable shortcut - that keeps the "Hard" rating honest.
    $msFlag = New-CTFFlag -Location "Modifiable Service (exploit)" -Description "binPath reconfigured -> command ran as SYSTEM" -Points 45 -Difficulty "Hard" -Technique "Modifiable service DACL -> SYSTEM"
    $msFlagDir = "C:\ProgramData\OCLab"
    if (!(Test-Path $msFlagDir)) { New-Item -Path $msFlagDir -ItemType Directory -Force | Out-Null }
    $msFlagPath = "$msFlagDir\modsvc_flag.txt"
    (Enc-Flag $msFlag) | Out-File $msFlagPath -Force
    # GATE: strip inheritance; grant only SYSTEM + Administrators (must escalate to read).
    icacls $msFlagPath /inheritance:r /grant "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null

    Write-Host "  Modifiable-service DACL vulnerability configured with flags" -ForegroundColor Green
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

    # Start SSH service. The sshd service can take a moment to register after
    # Add-WindowsCapability; wait for it to exist first, otherwise Set-Service
    # silently no-ops and sshd stays at Manual startup -> SSH (Flags 18/19) does
    # NOT come back after the post-build reboot.
    for ($i = 0; $i -lt 30 -and -not (Get-Service sshd -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Seconds 2 }
    Set-Service -Name sshd -StartupType 'Automatic'
    Start-Service sshd -ErrorAction SilentlyContinue

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
    sc.exe description WeakPermService "Weak Permission Service - token:$(Enc-Flag $svcDescFlag)"
    sc.exe sdset WeakPermService "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)(A;;RPWP;;;WD)"
    
    Write-Host "  Additional vulnerable services created" -ForegroundColor Green
}

# Function to configure scheduled tasks with flags
function Create-VulnerableScheduledTasks {
    Write-Host "Creating vulnerable scheduled tasks with flags..." -ForegroundColor Yellow
    
    # Task flag
    $taskFlag = New-CTFFlag -Location "Scheduled Task" -Description "VulnTask output" -Points 25 -Difficulty "Medium" -Technique "Scheduled task abuse"
    
    # Create task with stored credentials that writes flag
    $action = New-ScheduledTaskAction -Execute "C:\Windows\System32\cmd.exe" -Argument "/c echo $(Enc-Flag $taskFlag) > C:\Public\taskflag.txt"
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
    New-ItemProperty -Path "HKLM:\SOFTWARE\VulnApp" -Name "LicenseKey" -Value (Enc-Flag $regFlag1) -Force
    
    # Medium flag in HKCU
    $regFlag2 = New-CTFFlag -Location "Registry HKCU" -Description "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Points 25 -Difficulty "Medium" -Technique "Persistence mechanism review"
    # As SYSTEM, an HKCU: write lands in SYSTEM's hive (HKU\S-1-5-18), which the student never sees. Seed
    # it into the DEFAULT profile template so overclock's first-login profile inherits it in its own HKCU
    # Run key (the profile doesn't exist yet at build time, so we can't write overclock's hive directly).
    $regRunVal = "cmd /c echo $(Enc-Flag $regFlag2)"
    $defDat3 = "C:\Users\Default\NTUSER.DAT"
    if (Test-Path $defDat3) {
        reg load "HKU\OCDEF3" $defDat3 2>$null | Out-Null
        $ocRun = "Registry::HKEY_USERS\OCDEF3\Software\Microsoft\Windows\CurrentVersion\Run"
        New-Item -Path $ocRun -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path $ocRun -Name "UpdaterFlag" -Value $regRunVal -Force -ErrorAction SilentlyContinue | Out-Null
        [gc]::Collect(); Start-Sleep -Milliseconds 300; reg unload "HKU\OCDEF3" 2>$null | Out-Null
    }
    
    # Hard flag in service registry
    $regFlag3 = New-CTFFlag -Location "Registry Service" -Description "Service ImagePath" -Points 35 -Difficulty "Hard" -Technique "Service registry analysis"
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VulnScanner" -Name "Flag" -Value (Enc-Flag $regFlag3) -Force
    
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
<!-- app-config-token: $(Enc-Flag $webFlag1) -->
<form method="GET">
    Username: <input type="text" name="user"><br>
    Password: <input type="password" name="pass"><br>
    <input type="submit" value="Login">
</form>
</body>
</html>
"@
    $vulnPage | Out-File "C:\inetpub\wwwroot\vulnapp\login.html" -Encoding ASCII

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
    # DISABLED BY DESIGN (v5 realism pass): the on-box answer key is a security
    # no-no for a student-distributed script. Produce it off-box, admin-only, with
    # Generate-AnswerKey.py. This function is a neutered stub kept for compatibility.
    Write-Host "  [answer key] On-box report disabled; use Generate-AnswerKey.py (admin, off-box)." -ForegroundColor DarkYellow
    return $null

    # --- unreachable legacy body (kept for reference; never executes) ---
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

# Enable RDP + grant the low-priv student account interactive logon.
# WHY: SeDebugPrivilege (FLAG 4) and AlwaysInstallElevated (FLAG 16) are PRIVILEGE-abuse
# techniques that only work from an INTERACTIVE logon token. A pure WinRM/evil-winrm
# (network) logon STRIPS SeDebug from the token and msiexec can't elevate non-interactively.
# Real servers almost always have RDP enabled, so we enable it here and put `overclock`
# in Remote Desktop Users: the student RDPs in with looted creds, gets a full interactive
# token, and can then perform the privilege-abuse escalations for real.
function Enable-RDPAccess {
    Write-Host "Enabling RDP + interactive logon for the student account..." -ForegroundColor Yellow
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 0 -ErrorAction SilentlyContinue
    # Require NLA (secure/realistic default; FreeRDP/mstsc both support it).
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1 -ErrorAction SilentlyContinue
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    Set-Service -Name TermService -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name TermService -ErrorAction SilentlyContinue
    net localgroup "Remote Desktop Users" overclock /add 2>$null
    Write-Host "  RDP enabled; overclock added to Remote Desktop Users" -ForegroundColor Green
}

# Main execution
Write-Host "`nStarting vulnerable server configuration v5 ..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Run all configurations
Create-WeakUsers
Enable-RDPAccess
Disable-SecurityFeatures
Configure-MimikatzVulnerabilities
# SeDebugPrivilege privesc is NOT used on the server: it requires the low-priv user's token to carry
# SeDebug, but this box runs UAC ON (needed for the AlwaysInstallElevated flag), and UAC strips SeDebug
# from every non-elevated token -- so a standard user can never hold it here. SeDebug lives on the
# WORKSTATION box (UAC off) instead (complementary split -- both techniques practiced, each where it works).
# Configure-DebugPrivileges   # intentionally disabled (UAC-on incompatible with non-admin SeDebug)
Configure-PassTheHash
Configure-VulnerableRDP
Configure-VulnerableSMB
Create-UnquotedServicePaths
Configure-AlwaysInstallElevated
Configure-ModifiableService
Configure-VulnerableSSH
Create-VulnerableServices
Create-VulnerableScheduledTasks
Create-RegistryFlags
Create-VulnerableWebApps
Enable-LegacyProtocols

# Additional misconfigurations
Write-Host "`nApplying additional misconfigurations..." -ForegroundColor Yellow

# AutoLogon creds left in the registry as a realistic cleartext-credential loot artifact (a classic
# Winlogon disclosure), BUT AutoAdminLogon is OFF: if overclock were auto-logged into the console,
# an RDP connection as overclock reconnects to that console session instead of starting a fresh one,
# which breaks the interactive RDP privesc path (SeDebug/AIE). Students RDP in with looted creds.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -Value "overclock"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -Value "Administrator2025!"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value 0

# Store credentials
cmdkey /add:DC01 /user:Administrator /pass:$LabPassword
cmdkey /add:FileServer /user:overclock /pass:Administrator2025!

# Enable PowerShell remoting without authentication
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true -ErrorAction SilentlyContinue
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true -ErrorAction SilentlyContinue

# --- LSASS service finalizer (runs LAST, after every secedit /areas USER_RIGHTS block) ---
# Guarantees OCLabBackup is RUNNING as svc_backup so its cleartext WDigest cred is resident in LSASS.
# Two things bit us during builds: (1) a later USER_RIGHTS secedit template races svc_backup's
# SeServiceLogonRight away -> we re-grant it here via the LSA API (additive/immediate, no template
# replace); (2) the account/service passwords could disagree -> we re-sync both to the same token, then
# start with retries. Idempotent and last, so nothing clobbers it.
if ((Get-Service OCLabBackup -ErrorAction SilentlyContinue) -and $global:OCSvcPwd) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class LsaRights {
  [StructLayout(LayoutKind.Sequential)] struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
  [StructLayout(LayoutKind.Sequential)] struct LSA_OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
  [DllImport("advapi32.dll", SetLastError=true)] static extern uint LsaOpenPolicy(IntPtr S, ref LSA_OBJECT_ATTRIBUTES O, uint A, out IntPtr H);
  [DllImport("advapi32.dll", SetLastError=true)] static extern uint LsaAddAccountRights(IntPtr H, byte[] Sid, LSA_UNICODE_STRING[] R, uint C);
  [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr H);
  [DllImport("advapi32.dll")] static extern int LsaNtStatusToWinError(uint s);
  public static int Grant(byte[] sid, string right) {
    LSA_OBJECT_ATTRIBUTES oa = new LSA_OBJECT_ATTRIBUTES(); IntPtr ph;
    uint st = LsaOpenPolicy(IntPtr.Zero, ref oa, 0x00000810, out ph);
    if (st != 0) return LsaNtStatusToWinError(st);
    LSA_UNICODE_STRING[] r = new LSA_UNICODE_STRING[1];
    r[0].Buffer = Marshal.StringToHGlobalUni(right);
    r[0].Length = (ushort)(right.Length*2); r[0].MaximumLength = (ushort)((right.Length+1)*2);
    st = LsaAddAccountRights(ph, sid, r, 1); LsaClose(ph);
    return LsaNtStatusToWinError(st);
  }
}
'@ -ErrorAction SilentlyContinue
    try {
        $sidO = New-Object System.Security.Principal.SecurityIdentifier((Get-LocalUser $global:OCSvcAcct).SID.Value)
        $sidB = New-Object byte[] $sidO.BinaryLength; $sidO.GetBinaryForm($sidB, 0)
        [LsaRights]::Grant($sidB, "SeServiceLogonRight") | Out-Null
    } catch {}
    Set-LocalUser $global:OCSvcAcct -Password (ConvertTo-SecureString $global:OCSvcPwd -AsPlainText -Force) -ErrorAction SilentlyContinue
    Enable-LocalUser $global:OCSvcAcct -ErrorAction SilentlyContinue
    & sc.exe config OCLabBackup obj= (".\" + $global:OCSvcAcct) password= "$global:OCSvcPwd" | Out-Null
    for ($si = 0; $si -lt 6; $si++) {
        if ((Get-Service OCLabBackup).Status -eq 'Running') { break }
        sc.exe start OCLabBackup | Out-Null
        Start-Sleep 3
    }
}

# NOTE: on-box answer-key report REMOVED by design (students must not dump flags).
# -GenerateFlagReport is accepted for compatibility but only prints this notice.
# Generate the instructor key off-box, admin-only: python3 Generate-AnswerKey.py
if ($GenerateFlagReport) {
    # Emit a VALUES-FREE manifest (seed + REAL loop-expanded flag locations/metadata, NO FLAG{} values).
    # Off-box Generate-AnswerKey.py derives values from the seed + these real keys. Admin-only.
    $manifest = [PSCustomObject]@{
        seed  = $global:OC_FLAG_SEED
        box   = "server"
        flags = @($global:FlagList | Select-Object FlagID, Location, Difficulty, Technique)
    }
    $manifest | ConvertTo-Json -Depth 5 | Out-File "C:\oc-flag-manifest.json" -Encoding UTF8
    Write-Host "  [answer key] Values-free manifest -> C:\oc-flag-manifest.json (no values; pull it, run Generate-AnswerKey.py off-box)." -ForegroundColor DarkYellow
}

Write-Host "`n========================================" -ForegroundColor Green
# Belt-and-suspenders: Add-WindowsCapability can register the sshd service LATE
# (the SSH-section Set-Service can run before the service exists), so re-assert
# Automatic startup at the very END when it definitely exists -- otherwise SSH
# (Flags 18/19) is Manual/Stopped after the required reboot.
# Add-WindowsCapability registers the sshd service TOO LATE for any in-build fix
# to catch it (it isn't registered even by end-of-script -- the build log shows
# "Service sshd was not found"). So DEFER the fix to boot time: an AtStartup task
# (SYSTEM) forces sshd Automatic + started once the service actually exists.
$sshFix = 'Set-Service sshd -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service sshd -ErrorAction SilentlyContinue'
$sshAct = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NonInteractive -WindowStyle Hidden -Command $sshFix"
$sshTrg = New-ScheduledTaskTrigger -AtStartup
$sshPrn = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
Register-ScheduledTask -TaskName 'EnsureSSHD' -Action $sshAct -Trigger $sshTrg -Principal $sshPrn -Force -ErrorAction SilentlyContinue | Out-Null
# best-effort immediate attempt too, in case sshd registered by now
Start-Sleep -Seconds 5
if (Get-Service sshd -ErrorAction SilentlyContinue) { Set-Service sshd -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service sshd -ErrorAction SilentlyContinue }

# --- DECOY canaries: punish a blind `Select-String FLAG{` sweep. The answer key
# / submission system MUST reject every FLAG{DECOY_*}.
if (-not (Test-Path "HKLM:\SOFTWARE\OCLab")) { New-Item -Path "HKLM:\SOFTWARE\OCLab" -Force -ErrorAction SilentlyContinue | Out-Null }  # guard: -Force on an existing key WIPES its values (clobbered the identify notes)
New-ItemProperty -Path "HKLM:\SOFTWARE\OCLab" -Name "AuditFlag" -Value "FLAG{DECOY_TRY_HARDER_A1}" -Force -ErrorAction SilentlyContinue | Out-Null
"Ops reminder: rotate creds monthly. FLAG{DECOY_NOT_HERE_B2}" | Out-File "C:\Public\ops_notes.txt" -Force
[Environment]::SetEnvironmentVariable("OC_AUDIT_TOKEN","FLAG{DECOY_KEEP_LOOKING_C3}","Machine")

Write-Host "Server vulnerability configuration v5 complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "MIMIKATZ-FRIENDLY FEATURES:" -ForegroundColor Cyan
Write-Host "  WDigest enabled (plaintext passwords in memory)" -ForegroundColor Yellow
Write-Host "  LSA Protection disabled" -ForegroundColor Yellow
Write-Host "  (SeDebug privesc intentionally OFF here -- lives on the workstation; UAC on for AIE)" -ForegroundColor DarkGray
Write-Host "  Pass-the-Hash enabled (NTLM)" -ForegroundColor Yellow
Write-Host "  Credential Guard disabled" -ForegroundColor Yellow
Write-Host ""
Write-Host "OTHER VULNERABILITIES:" -ForegroundColor Cyan
Write-Host "  Unquoted Service Paths (3 services)" -ForegroundColor Yellow
Write-Host "  AlwaysInstallElevated MSI" -ForegroundColor Yellow
Write-Host "  Modifiable Service DACL (SiteHealthSvc -> SYSTEM)" -ForegroundColor Yellow
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

# ================= OPTIONAL: join OVERCLOCK.LOCAL (VM1 / Domain Controller) =================
# Additive integration. All lab accounts above are LOCAL (New-LocalUser / net user), so a
# domain join changes nothing about the existing flags -- it only adds the AD attack surface
# hosted on the DC (VM1). Run with -JoinDomain (point -DCIP at the live DC).
if ($JoinDomain) {
    Write-Host ""
    Write-Host "[JoinDomain] Pointing DNS at $DCIP and joining $DomainName ..." -ForegroundColor Green
    $ifn = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1).Name
    Set-DnsClientServerAddress -InterfaceAlias $ifn -ServerAddresses $DCIP -EA SilentlyContinue
    $djSec  = ConvertTo-SecureString $DomainJoinPass -AsPlainText -Force
    $djCred = New-Object System.Management.Automation.PSCredential($DomainJoinUser, $djSec)
    try {
        Add-Computer -DomainName $DomainName -Credential $djCred -Force -EA Stop
        Write-Host "[JoinDomain] Joined $DomainName. Reboot required to apply." -ForegroundColor Green
        if ($Unattended) { Restart-Computer -Force }
    } catch {
        Write-Host "[JoinDomain] FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
}
