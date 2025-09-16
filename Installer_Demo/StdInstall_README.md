# StdInstall.ps1

## Quick Reference Cheatsheet

These are the most common one-liners you’ll need:

```powershell
# Compute SHA-256 hash of installer
$hash = (Get-FileHash 'C:\Packages\7z.msi' -Algorithm SHA256).Hash

# Install MSI silently with hash validation
.\StdInstall.ps1 -Action install -Source 'C:\Packages\7z.msi' -DisplayName '7-Zip' -ExpectedSha256 $hash

# Install EXE with custom silent switches
.\StdInstall.ps1 -Action install -Source 'C:\Packages\AppSetup.exe' -DisplayName 'Contoso App' -ExeSilentArgs '/SILENT /VERYSILENT /NORESTART'

# Uninstall by ProductCode (preferred for MSI)
.\StdInstall.ps1 -Action uninstall -ProductCode '{23170F69-40C1-2702-2301-000001000000}'

# Uninstall by DisplayName
.\StdInstall.ps1 -Action uninstall -DisplayName '7-Zip'
```

---

## Overview
`StdInstall.ps1` is a standardized PowerShell script for **installing and uninstalling software** silently in regulated enterprise environments.  

It enforces modern operational standards:
- **Silent MSI/EXE installs** (idempotent, configurable)
- **SHA-256 validation** of installers
- **Robust logging** (UTC timestamps, daily folders under `ProgramData`)
- **Windows Event Log mirroring** (Application log, custom source)
- **Deterministic exit codes** (for ConfigMgr, Intune, BigFix, RPA, and regulatory pipelines)
- **Config enforcement hook** (e.g., registry/GPO enforcement after install)

This script is designed to be modular, reusable, and safe for regulated industries (NERC CIP, TSA, etc.).

---

## Prerequisites
- **PowerShell 5.1 or later** (tested on 5.1 and 7+)
- **Administrative rights** (required for installing/uninstalling software and writing Event Log entries)
- **Execution Policy** must allow running scripts (e.g. `Set-ExecutionPolicy RemoteSigned`)

---

## Getting the SHA-256 Hash
SHA-256 validation is **strongly recommended** before executing any installer.

Run the following in PowerShell:
```powershell
Get-FileHash 'C:\Path\to\Installer.msi' -Algorithm SHA256
```

Example output:
```
Algorithm : SHA256
Hash      : D64A3B6F4C4E0D7FA92308F...CDA10292A38F7F5AD5E39
Path      : C:\Path\to\Installer.msi
```

Use the **64-character hex string** in the `-ExpectedSha256` parameter.

---

## Usage Examples

### Install MSI with Hash Validation
```powershell
$hash = (Get-FileHash 'C:\Packages\7z.msi' -Algorithm SHA256).Hash
.\StdInstall.ps1 -Action install -Source 'C:\Packages\7z.msi' -DisplayName '7-Zip' -ExpectedSha256 $hash -Verbose
```

### Install EXE with Custom Silent Switches
```powershell
.\StdInstall.ps1 -Action install -Source 'C:\Packages\AppSetup.exe' `
  -DisplayName 'Contoso App' `
  -ExeSilentArgs '/SILENT /VERYSILENT /NORESTART' `
  -ExpectedSha256 'ABC123...'
```

### Install MSI with Extra Properties
```powershell
.\StdInstall.ps1 -Action install -Source 'C:\Packages\FinanceApp.msi' `
  -DisplayName 'FinanceApp' `
  -MsiProperties 'ALLUSERS=1 REBOOT=ReallySuppress' `
  -ExpectedSha256 $hash
```

### Uninstall by ProductCode
```powershell
.\StdInstall.ps1 -Action uninstall -ProductCode '{23170F69-40C1-2702-2301-000001000000}' -Verbose
```

### Uninstall by DisplayName
```powershell
.\StdInstall.ps1 -Action uninstall -DisplayName 'Legacy Agent' -Verbose
```

---

## Parameters

| Parameter           | Required? | Description |
|---------------------|-----------|-------------|
| **`-Action`**       | Yes       | `install` or `uninstall`. |
| **`-Source`**       | Yes (for install) | Path or URL to MSI/EXE installer. |
| **`-ExpectedSha256`** | Recommended | SHA-256 hash of installer. Blocks execution if mismatch. |
| **`-ProductCode`**  | Optional | MSI product code GUID for uninstall/detection. |
| **`-DisplayName`**  | Optional | Friendly name for detection via registry. |
| **`-ExeSilentArgs`** | Optional | Silent switches for EXE installers. Default: `/S /v"/qn /norestart"`. |
| **`-MsiProperties`** | Optional | Extra MSI properties passed to `msiexec`. (See table below). |
| **`-LogRoot`**      | Optional | Root folder for logs. Default: `%ProgramData%\AppStdInstall\Logs`. |
| **`-EnforceConfig`** | Switch | Runs a sample config enforcement step after install. |
| **`-EventLogName`** | Optional | Windows Event Log to mirror logs into. Default: `Application`. |
| **`-EventSource`**  | Optional | Event log source name. Default: `AppStdInstall`. |
| **`-TimeoutSeconds`** | Optional | Maximum seconds to wait for installer/uninstaller to complete (default: 1800 / 30 min). Prevents “hanging” EXE installs. |
| **`-ExpectedExitCodes`** | Optional | List of exit codes to treat as success (default: `0, 1641, 3010`). Useful for EXEs/MSIs that return “restart required” codes. |

---
## Common MSI Properties

When using `-MsiProperties`, you can pass additional options to fine-tune MSI installs.  
Below are **commonly used properties**:

| Property | Example | Purpose |
|----------|---------|---------|
| **`ALLUSERS=1`** | `ALLUSERS=1` | Install for all users (machine-wide). |
| **`ALLUSERS=""`** | `ALLUSERS=""` | Install per-user only. |
| **`REBOOT=ReallySuppress`** | `REBOOT=ReallySuppress` | Prevent automatic reboot after install. |
| **`ADDLOCAL`** | `ADDLOCAL=ALL` | Installs all available features. Or comma-separated list, e.g. `ADDLOCAL=FeatureA,FeatureB`. |
| **`REMOVE`** | `REMOVE=FeatureC` | Removes specific features. |
| **`INSTALLDIR`** | `INSTALLDIR="C:\CustomPath\App"` | Overrides the default installation directory. |
| **`TRANSFORMS`** | `TRANSFORMS=custom.mst` | Apply a transform (`.mst`) file for customizations. |
| **`QN`** (switch) | `/qn` | Tells `msiexec` to run with no UI (quiet mode). Already included by the script. |
| **`/norestart`** (switch) | `/norestart` | Suppresses automatic restarts. Already included by the script. |

📖 **Reference**: [Microsoft official msiexec documentation](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)

---
## Why Some EXE Installers May Hang

Unlike MSI packages, many vendor-provided `.exe` installers are just **bootstrapper wrappers**.  
They can appear to “hang” because:

- They **spawn a child `msiexec` process** and never exit themselves.  
- They wait for **EULA acceptance or user prompts** that aren’t bypassed unless you supply the right properties (e.g. `ACCEPT_EULA=1`).  
- They return **restart-required codes** (`3010`, `1641`) instead of `0`, which can look like a failure to automation.  
- Logging isn’t enabled by default, so it’s unclear whether progress is being made.  

➡️ Always use `-TimeoutSeconds` and `-ExpectedExitCodes` to prevent long-running automation jobs from hanging indefinitely.

---

## Logging

- **File logs**: `%ProgramData%\AppStdInstall\Logs\YYYYMMDD\AppStdInstall_<Action>_<Host>_<Timestamp>.log`
- **MSI logs**: Stored in the same folder, one per run.
- **Event Log**: Mirrors INFO/WARN/ERROR entries to the `Application` log.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| **0**  | Success |
| **10** | Already in desired state (idempotent) |
| **20** | Source not found / download failed |
| **21** | SHA-256 mismatch |
| **22** | SHA-256 could not be computed |
| **30** | Install/Uninstall process failed |
| **31** | Install/Uninstall returned non-zero |
| **40** | Detection failed (post-check mismatch) |
| **50** | Config enforcement failed |
| **98** | Event Log init failed (script continued) |
| **99** | Unexpected error |

---

## Workflow Reference

### Install Workflow

| Step | Action | Possible Exit Codes |
|------|--------|----------------------|
| 1 | Detect if already installed | 10 |
| 2 | Validate source | 20 |
| 3 | Verify SHA-256 (if provided) | 21 (mismatch), 22 (hash error) |
| 4 | Run installer | 30 (failed to launch), 31 (non-zero exit) |
| 5 | Verify installation | 40 |
| 6 | Enforce config (optional) | 50 |
| 7 | Success | 0 |

### Uninstall Workflow

| Step | Action | Possible Exit Codes |
|------|--------|----------------------|
| 1 | Detect if present | 10 |
| 2 | Run uninstall | 30 (failed to launch), 31 (non-zero exit) |
| 3 | Verify removal | 40 |
| 4 | Success | 0 |

---

## Notes
- Avoids `Win32_Product` (no WMI consistency check side-effects).
- Fully idempotent: safe to rerun multiple times.
- UTC timestamps = SIEM/central logging friendly.
- Compatible with **PowerShell 5.1 and 7+**.

---

## License
MIT (adapt/extend for your org’s standards).
