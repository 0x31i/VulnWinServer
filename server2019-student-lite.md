# Windows Server 2019: Student Lite Guide
### overclock Security | Offensive Track | The map, not the turn-by-turn

> **What this is.** The high-level narrative of the engagement: phase by phase, what to accomplish
> and which tools to reach for, with just enough to point you at the water so you work out the how
> yourself. For the exact commands, real output, and the full reasoning behind every move, use the
> **Student Walkthrough**, or the **Hybrid** page, which folds both together and hides the detail
> until you are stuck.

**Target:** `192.168.148.101` (Windows Server 2019 Build 17763) | **Attacker:** Kali Linux | **Related hosts:** the Win10 workstation (`192.168.148.102`), the OCWA web server | **24 flags**

> **The golden rule.** This is the **crown jewel**, the convergence host where the whole engagement lands.
> Nothing is a free grep. Most flags are **base64** (decode them); a handful stay plaintext because the
> *technique* is the point (the ssh banner, the hidden username, LSASS, ADS). A `findstr /s FLAG{ C:\*`
> returns only **decoys**. Learn to spot markers like `token:`, `Legacy access token:`, `app-config-token:`.
> This is a **workgroup** box, so every `nxc` command needs `--local-auth`.

---

## Setup & mindset
- Attack from **Kali**: `nxc`, `nmap`, `smbclient`/`smbmap`, `evil-winrm`, `impacket-scripts`, `ssh`, `mimikatz`.
- **Workgroup** box: your `nxc` commands need the local-auth switch.
- **The rule:** most flags are **base64** (decode with `d3coder`). Look for markers like `token:`, `Legacy
  access token:`, `app-config-token:`. A few stay plaintext because the *technique* is the point. A plain
  `findstr FLAG{` finds only **decoys**.
- This server is the **objective**, and creds you loot elsewhere tend to work here.

## Switches to try (your enumeration toolbox)
The whole box is enumerable with a handful of tools. Learn what each *switch* gathers, then aim it at the
right target. This table is the core of the lite guide: pick a switch, run it, read the output.

**`nxc smb <ip> [--local-auth]` (the workhorse):**
| Switch | What it gathers |
|--------|-----------------|
| `--users` | local accounts **with descriptions** (Flags 1) |
| `--rid-brute` | walks SIDs to reveal accounts `--users` will not (Flag 2); works with just `-u guest -p ''` |
| `--shares` | SMB shares and your READ/WRITE level on each (Flags 6-9) |
| `--sam` | dumps local NT password hashes (needs admin; Flags 4, 10) |
| `--pass-pol` | password policy (spray safely) |
| `-x "<cmd>"` | run a Windows command on target (`sc`, `reg`, `type`, `whoami`) |
| `-X "<ps>"` | run PowerShell (`Get-ItemProperty`, `Get-CimInstance`, `Get-ScheduledTask`) |
| `-H <hash>` | authenticate with an NT hash instead of a password (Pass-the-Hash) |
| `--continue-on-success` | keep spraying after the first hit, so you find *all* valid creds |

**`nmap`:** `-sV` (service versions), `-Pn` (skip ping), `-p-` (all ports), `-sC` (default scripts), `-A`
(aggressive), `-T4` (faster).
**`smbclient //ip/Share`:** `-N` (anonymous), `-U user%pass` (authenticated), `-c 'get <file>'` (one-shot
download); or `smbmap -H ip -u .. -p .. -R` to recurse every share at once.
**Reading things on-target (via `-x`/`-X`):** `sc qdescription <svc>`, `reg query <key> /v <val>`,
`Get-ItemProperty '<key>'`, `Get-CimInstance Win32_UserAccount`, `Get-Content <file> -Stream <name>`.

---

## Phase 1: Reconnaissance

> **The thinking.** This is the crown-jewel host and we have touched nothing yet, so the first job is to map
> the attack surface before we spend any credential. A server exposes more doors than a workstation (ssh,
> HTTP, SMB, RDP, WinRM), and we want to know which classes of attack are even possible before we commit. We
> also harvest whatever a service volunteers pre-auth (the ssh banner, page source) because that costs
> nothing and tends to seed the next stage. Recon comes first because every later decision (which port,
> which credential, which share) depends on knowing what is actually listening.

**Goal.** Map a broad surface (this box runs more than a workstation) and grab free intel before you have any creds.
**Try.** A service scan (`nmap -sV <target>`). Expect ssh, HTTP, SMB, RDP, WinRM. Each open port is a door,
and two of them (ssh, HTTP) hand you a flag pre-auth if you just read what they volunteer.

### FLAG 17: ssh login banner (Easy)

**Goal.** Some services hand you a flag just for connecting. Read what ssh serves before you log in.
**Try.** Trigger the ssh banner without authenticating (`ssh -o PreferredAuthentications=none nobody@<target>`).
The banner prints in plaintext, no decode needed.

### FLAG 24: web portal HTML comment (Easy)

**Goal.** The root page just redirects. Read the raw source, not the rendered page, and follow the redirect to the real app.
**Try.** `curl -s http://<target>/ | grep -i "<!--"` to find the redirect, then read the `/vulnapp/login.html`
source for a base64 `app-config-token:` comment. Decode it. *(This is the box's one web surface — the realistic
way to work it is proxying the browser through **Burp**; `curl | grep '<!--'` and `view-source:` show the same.)*

---

## Phase 2: User & service discovery

> **The thinking.** Recon told us the doors; now we ask who and what lives behind them so we can aim a
> credential attack. This phase answers "which accounts exist and which services are misconfigured," because
> you cannot spray or target what you have not enumerated. It comes before initial access on purpose: names
> and service metadata are readable with guest-level or first-credential access, and building that inventory
> now means Phase 3's spray is precise instead of noisy. The tradeoff is patience, we resolve accounts the
> hard way (RID cycling) rather than assume the "list users" block stopped us.

**Goal.** Inventory accounts and service metadata so Phase 3's spray is precise, not noisy.
**Try.** RID-cycling (`--rid-brute`) for hidden accounts, `--users` for descriptions, `sc qdescription` and the
Terminal Server registry key for service and RDP metadata. Metadata fields are where the tokens hide.

### FLAG 2: the hidden username (Easy)

**Goal.** One account is named after a flag but hidden from normal listings. Find it without a credential.
**Try.** RID-cycling (`nxc smb ... -u guest -p '' --rid-brute`) walks SIDs and resolves each to a name, even
when `--users` is blocked. The flag is the account name itself, plaintext.

### FLAG 1: admin's user description (Easy)

**Goal.** Once you have any working credential, read the account metadata. The `overclock` user's Description is the flag.
**Try.** Enumerate users with their descriptions (`--users`, or `rpcclient querydispinfo`). This one is
plaintext, a warm-up that also confirms your credential can enumerate.

### FLAG 19: weak service description (Easy)

**Goal.** A suspiciously named service hides a base64 token in its Description.
**Try.** Read service metadata (`sc qdescription WeakPermService`); one carries a base64 `token:`. Decode it.

### FLAG 5: RDP certificate comment (Medium)

**Goal.** RDP settings live in the registry, and a comment field holds a base64 token.
**Try.** Read the Terminal Server key's `CertificateComment` value (`Get-ItemProperty '...\Terminal Server'`)
and decode the base64.

---

## Phase 3: Initial access & SMB shares

> **The thinking.** We now have names and a map, so this is where enumeration turns into a real foothold. The
> phase answers "which credentials actually work, and what does each unlock," which is why spraying the
> discovered accounts comes right before enumerating shares. The 3-tier share layout (anonymous,
> authenticated, admin) is deliberately teaching the access ladder, so the key decision is to re-enumerate at
> every privilege level we reach rather than settle for the first door that opens. The tradeoff is discipline:
> it is tempting to grab the anonymous share and move on, but the admin tier is where the interesting loot sits.

**Goal.** Turn enumeration into a foothold: spray the discovered accounts, then climb the share access ladder.
**Try.** Password spraying (`nxc smb ... -u users.txt -p passwords.txt --local-auth --continue-on-success`),
then `--shares` to see your READ/WRITE level. Some shares are anonymous, some need creds, one needs admin.
*(Same job in **Metasploit**: `auxiliary/scanner/smb/smb_login` sprays; `exploit/windows/smb/psexec` turns admin
creds into a Meterpreter SYSTEM shell — accepts a hash in `SMBPass` for pass-the-hash.)*

### FLAGs 6-8: the three shares (Easy / Medium / Hard)

**Goal.** Climb the access ladder: anonymous, then authenticated, then admin. Flag 8 proves you reached admin.
**Try.** Each share (**Public** = anonymous, **Backup** = needs creds, **IT** = needs admin) holds a
`README_ACCESS.txt` with a base64 "Legacy access token". Pull each with `smbclient` and decode.

### FLAG 9: password file in Public (Easy)

**Goal.** A `passwords.txt` in the world-readable Public share holds a real admin cred and a base64 token.
**Try.** Pull `passwords.txt` from Public and decode the `svc_token`. Save the Administrator credential; it unlocks Phases 4 and 5.

---

## Phase 4: Credentials, SAM & hidden data

> **The thinking.** We have admin on the box but not yet SYSTEM, so this phase is about harvesting the
> credential material and hidden data that turns one foothold into many. It answers "what secrets does this
> host store that reach other accounts and other hosts," which is why we dump the SAM and hunt hidden streams
> and key files now, before attempting the SYSTEM-level escalations. It comes after initial access because
> most of these reads require the admin credential we just proved, and before Phase 5 because the hashes we
> pull here (and the reuse they enable) feed Pass-the-Hash. The key decision is to loot broadly, hashes, ADS,
> ssh keys, rather than tunnel-vision on a single path to SYSTEM.

**Goal.** Harvest credential material and hidden data that turns one foothold into many.
**Try.** Dump the SAM (`--sam` / `secretsdump`), hunt Alternate Data Streams (`Get-Content -Stream`), and read
the ssh key file. Loot broadly rather than tunnel-vision on one path.

### FLAG 10: SAM backup (two-part: Identify Medium / Exploit Hard)

**Goal.** Spot that SAM/SYSTEM hive backups live in `C:\Backup` (Part 1), then extract the SAM and recover the
gated secret only a real dump reaches (Part 2).
**Try.** Sweep for backup dirs -> read `C:\Backup\README.txt` (identify); then `impacket-secretsdump` and read
the admin-gated `C:\Backup\sam_backup_info.txt` (exploit).

### FLAG 11: Alternate Data Stream (Hard)

**Goal.** `C:\Public\normal.txt` looks ordinary but NTFS lets it carry a hidden stream. Read it.
**Try.** List streams first (`Get-Item ... -Stream *` or `dir /r`), then read the extra `hidden` stream
(`Get-Content ... -Stream hidden`). Note: `type` cannot read a named stream. This one is plaintext.

### FLAG 18: ssh authorized_keys comment (Medium)

**Goal.** The Windows OpenSSH server stores admin keys on disk, and the key comment carries the flag.
**Try.** Read `C:\ProgramData\ssh\administrators_authorized_keys` and check the comment at the end of the key line. Plaintext.

---

## Phase 5: Privilege escalation to SYSTEM

> **The thinking.** Admin is not the finish line on Windows, SYSTEM is, and several flags here deliberately sit
> in the SYSTEM profile so the only way to read them is to actually escalate. This phase answers "can we cross
> from Administrator to SYSTEM," and it comes after looting because the hashes and misconfigurations we found
> are the raw material for these attacks. We work several independent routes (LSASS/LSA secrets, Pass-the-Hash,
> AlwaysInstallElevated, modifiable service DACL) on purpose, because in a real assessment you want more than one path
> to the top in case one is patched or monitored. The tradeoff is noise: these are the loudest techniques in
> the engagement, so on a real target you would pick the quietest working route rather than run them all.

**Goal.** Cross from low-priv `overclock` to SYSTEM. Each escalation is **two parts**, Part 1 *identify*
(readable as `overclock`) + Part 2 *exploit* (a flag ACL-locked to SYSTEM+Administrators, or living only in
LSASS). Reading Part 2 with the recovered admin cred skips the lesson, do it from `overclock`.
**Try.** Enumerate first (`reg query`/`secedit`/`dir`) to discover each artifact, then perform the technique.

### FLAG 3: credentials in LSASS (two-part: Identify Medium / Exploit Hard)

**Goal.** Prove the box leaks cleartext from memory (Part 1), then recover a credential that lives *only* in
LSASS (Part 2). No registry shortcut.
**Try.** Confirm WDigest on / LSA Protection off, enumerate `HKLM\SOFTWARE\OCLab`, then dump LSASS with
`mimikatz` / `lsassy`, the recovered `svc_backup` cleartext **is** the exploit flag.

### FLAG 4: Pass-the-Hash (two-part: Identify Medium / Exploit Hard)

**Goal.** Confirm the box accepts hash-based auth (Part 1), then replay a hash into a SYSTEM shell (Part 2).
**Try.** Check `LmCompatibilityLevel`/`FilterAdministratorToken`, read `PthNote`, then
`impacket-psexec -hashes` -> SYSTEM -> `pth_success.txt`.

### FLAG 15: AlwaysInstallElevated (two-part: Identify Medium / Exploit Hard)

**Goal.** Confirm the policy is enabled in both hives (Part 1), then run a malicious MSI that reads a
SYSTEM-only flag (Part 2).
**Try.** `reg query` HKLM+HKCU, read `C:\Public\msi_hint.txt`, then `msfvenom -f msi` -> SYSTEM -> `msi_flag.txt`.
*(Easy button: from a Meterpreter session, `exploit/windows/local/always_install_elevated` builds+runs the MSI
for you — needs an interactive medium-integrity session.)*

### FLAG 16: Modifiable service DACL -> SYSTEM (two-part: Identify Medium / Exploit Hard)

**Goal.** Spot a service a normal user can reconfigure (Part 1), then rewrite its `binPath` and restart it to
run your command as SYSTEM (Part 2).
**Try.** `accesschk -uwcqv overclock *` (or `sc.exe sdshow SiteHealthSvc`) to find `SERVICE_CHANGE_CONFIG`, read
`C:\Public\service_permissions.txt`, then `sc.exe config SiteHealthSvc binPath= …` + restart -> SYSTEM ->
`C:\ProgramData\OCLab\modsvc_flag.txt`.

---

## Phase 6: Service & registry mining

> **The thinking.** We already own the box, so this phase is the thorough sweep that a real assessment does not
> skip, mining services, autoruns, scheduled tasks, and registry hives for the misconfigurations and secrets
> that give persistence. It answers "what else on this host would let us regain SYSTEM or survive a reboot,"
> which is why it comes last, after the foothold and escalation are settled and we can read freely. The
> techniques (unquoted paths, Run keys, task actions, service registry values) double as flag locations
> because both are code or data that survives a reboot. The decision here is completeness over speed:
> with the box owned, we document every persistence and privilege foothold rather than stop at the first one.

**Goal.** Sweep the box for persistence and privilege footholds: unquoted services, autoruns, tasks, registry hives.
**Try.** Filter for unquoted service paths (`Get-CimInstance Win32_Service` or `wmic service get name,pathname`),
then read scheduled-task output and named registry values. Persistence locations double as flag locations.

### FLAGs 12-14: unquoted service paths (two-part: Identify Easy / Exploit Hard)

**Goal.** Spot three services with unquoted paths + writable base dirs (Part 1), then hijack the unquoted path
to run as SYSTEM and read a SYSTEM-only flag (Part 2). Each service is one two-part flag.
**Try.** Enumerate unquoted services -> `icacls`/`dir` the base dir for `service_info.txt` (identify); then drop
a binary at the unquoted injection point -> SYSTEM -> the gated `scanner_flag.txt` / `commonapp_flag.txt` / `vendor_flag.txt`.

### FLAGs 20-23: scheduled task & registry (Medium / Hard)

**Goal.** Four autostart and registry spots, each a different survive-a-reboot mechanism.
**Try.** Read a scheduled task's output file, an application license key, a per-user Run key, and a service
registry value. Enumerate Run keys (HKCU and HKLM), service ImagePaths, and task actions, then decode each base64.

---

## Cross-host context

> **The thinking.** This server is the top of the local chain and the convergence point of the wider
> engagement. Get to SYSTEM here and you own the box outright. The crown jewel is not a single file, it is what
> the looted credentials unlock, so we replay creds from the other hosts against this one.

**Goal.** Test what looted creds unlock here. This box is where the whole lab converges.
**Try.** The `localadmin` / `Administrator123` credential from the **Win10 workstation** and `user1` /
`Password123!` from the **OCWA web server** both authenticate here (Pass-the-Hash or straight reuse).

---

## Flag checklist

*(Censored. Confirm each with your own decode.)*

| # | Flag | # | Flag | # | Flag |
|---|------|---|------|---|------|
| 1 | FLAG{M******5} | 9 | FLAG{S******3} | 17 | FLAG{T******6} |
| 2 | FLAG{P******5} | 10 | FLAG{H******8} | 18 | FLAG{S******8} |
| 3 | FLAG{M******6} | 11 | FLAG{F******9} | 19 | FLAG{F******2} |
| 4 | FLAG{P******4} | 12 | FLAG{T******5} | 20 | FLAG{C******9} |
| 5 | FLAG{G******5} | 13 | FLAG{P******5} | 21 | FLAG{M******1} |
| 6 | FLAG{S******0} | 14 | FLAG{S******6} | 22 | FLAG{C******6} |
| 7 | FLAG{E******7} | 15 | FLAG{K******2} | 23 | FLAG{M******2} |
| 8 | FLAG{J******7} | 16 | FLAG{M******7} | 24 | FLAG{A******4} |

> **Decoys.** `FLAG{DECOY_*}` strings are planted in obvious grep spots (`C:\Public\ops_notes.txt`, an `OCLab`
> registry value, the `OC_AUDIT_TOKEN` environment variable). The answer key rejects them. No-decode = fake.
