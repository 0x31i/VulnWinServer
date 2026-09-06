<p align="center">
  <img src="assets/vulnWinserver-logo.jpg" alt="VulnWinServer" width="820">
</p>

# VulnWinServer: OVERCLOCK Lab (Windows Server 2019)

A deliberately vulnerable Windows Server 2019 box, one target in the **OVERCLOCK**
offensive-security lab (the NGS x GCU Hacknet project). A single PowerShell script
turns a clean Server 2019 VM into a Windows privilege-escalation, service-abuse, and
credential-dumping range with **32 capture-the-flag objectives**.

> **This box is intentionally insecure.** Build it only on an isolated VM with no
> route to a production network or the public internet. You are responsible for how
> and where you run it.

---

## What you will practice

A member-server attack surface focused on service misconfiguration, SMB, and
credential theft:

- **Privilege escalation to SYSTEM:** unquoted service paths, modifiable service
  DACLs, scheduled-task abuse, `AlwaysInstallElevated` MSI abuse.
- **Enumeration:** service and registry analysis, unquoted-path discovery, SMB
  share enumeration, RDP and configuration review, alternate-data-stream (ADS)
  discovery, SSH-key hunting.
- **Credential access:** Mimikatz `sekurlsa`, SAM database extraction,
  Pass-the-Hash to admin, backup/file mining, persistence-mechanism review.

**Flags:** 32 total: 12 Easy, 12 Medium, 8 Hard, each mapped to a specific
technique.

---

## Requirements

| | |
|---|---|
| **Target VM** | Windows Server 2019, fresh install, **snapshot it first** |
| **Resources** | 2+ vCPU, 4 GB+ RAM, 60 GB disk |
| **Privilege** | Run the build script in an **elevated** PowerShell (Administrator) |
| **Attacker box** | Kali Linux (or any pentest distro) on the same isolated host-only network |
| **Networking** | Host-only / internal network. **No internet, no production LAN.** |

---

## Build it

1. Snapshot the clean VM so you can roll back.
2. Copy `vulnwinserver.ps1` onto the target.
3. Open **PowerShell as Administrator**:

   ```powershell
   Set-ExecutionPolicy -Scope Process -Bypass -Force
   .\vulnwinserver.ps1
   ```

4. Let it finish, then reboot. The box is ready to attack from Kali.

### Flags and the build seed (important)

Flags look like `FLAG{CODENAME12345678}` and are **derived, never stored**:
`Select-String "FLAG{"` against the source finds nothing:

```
flag   = FLAG{ codename + 8 digits }
digits = HMAC_SHA256( seed , "server::<location>" )   (folded to 8 digits)
```

The script reads the seed from **`OC_FLAG_SEED`**:

- **Home / practice (recommended): do nothing.** With no seed set, the script
  generates a random one, prints it, and builds with it. Save the printed value if
  you want to check your own answers later.
- **Reproducible personal build:** `$env:OC_FLAG_SEED = "my-personal-seed"` before
  running.

Your home-built flags **will not match the official graded lab**; that instance
uses a private course seed you do not have. This keeps the box fully playable while
keeping the official answers uncomputable from this public script.

---

## How to play

| File | Use it when |
|---|---|
| `server2019-student-lite.md` | **Hints only**, no answers. |
| `server2019-hybrid.md` | Hint **plus** a per-flag collapsible reveal. |
| `server2019-student-walkthrough.md` | Full step-by-step walkthrough. |
| `server2019-student-walkthrough-wiki.md` | Same content, wiki/portal formatting. |

Start with the lite hints, fall back to the hybrid reveal, confirm with the full
walkthrough. Flag values in the student writeups are **masked** (`FLAG{S******8}`);
you submit the real ones recovered from your own box.

---

## Troubleshooting

- **Script blocked:** confirm the elevated shell + the `Set-ExecutionPolicy` line.
- **A flag will not resolve:** rebuild from the clean snapshot.
- **Reset the flags:** roll back and rebuild with a different `OC_FLAG_SEED`.

---

## License / use

For authorized training and education only. Do not deploy on any system or network
you do not own or have explicit permission to test.
