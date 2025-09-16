<#PSScriptInfo
.VERSION 1.0.0
.GUID 7d07b3c8-89d2-4593-9b06-8a32161937b6
#>

<#
.SYNOPSIS
  Standardized silent install/uninstall with optional SHA-256 validation, logging, and event log mirroring.

.DESCRIPTION
  Installs or uninstalls a given application (MSI/EXE) silently, validates the
  installer with SHA-256 (optional but recommended), writes UTC timestamped logs
  to disk, mirrors logs to the Windows Event Log, and returns deterministic exit codes.

.EXIT CODES
  0  = Success
  10 = Already in desired state (idempotent)
  20 = Download/Source not found
  21 = SHA-256 mismatch
  22 = SHA-256 could not be computed
  30 = Install/Uninstall failed (launcher)
  31 = Install/Uninstall returned non-zero
  40 = Detection failed (post-check unexpected state)
  50 = Configuration enforcement failed
  98 = Event Log initialization failed (non-fatal; continues)
  99 = Unexpected error

.PARAMETER Action
  install | uninstall

.PARAMETER Source
  Path or URL to installer binary (.msi or .exe). Not required for uninstall
  if ProductCode or DisplayName is provided.

.PARAMETER ExpectedSha256
  Hex string of the expected SHA-256 for the installer. If provided, the file
  is hashed and MUST match before execution (case-insensitive, no spaces).

.PARAMETER ProductCode
  MSI product code GUID for uninstall/detection.

.PARAMETER DisplayName
  Friendly display name for detection via Uninstall registry.

.PARAMETER ExeSilentArgs
  Custom silent args for EXE installers (defaults provided).

.PARAMETER MsiProperties
  Optional additional MSI properties (e.g. "ADDLOCAL=ALL").

.PARAMETER LogRoot
  Folder where logs are written (created if missing).

.PARAMETER EnforceConfig
  Switch to enforce a sample configuration item after install (example).

.PARAMETER EventLogName
  Windows Event Log name to mirror into (default: Application).

.PARAMETER EventSource
  Event Source name (default: AppStdInstall). Source is created if needed.

.EXAMPLE
  # Install 7-Zip with SHA-256 validation and config enforcement
  .\StdInstall.ps1 -Action install -Source 'C:\Packages\7z.msi' `
    -DisplayName '7-Zip' -ExpectedSha256 'abc123...hex...' -EnforceConfig -Verbose

.EXAMPLE
  # Uninstall by ProductCode
  .\StdInstall.ps1 -Action uninstall -ProductCode '{23170F69-40C1-2702-2301-000001000000}' -Verbose
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)]
  [ValidateSet('install','uninstall')]
  [string]$Action,

  [string]$Source,

  [ValidatePattern('^\{[0-9A-Fa-f\-]{36}\}$')]
  [string]$ProductCode,

  [string]$DisplayName,

  [string]$ExpectedSha256,

  [string]$ExeSilentArgs = '/S /v"/qn /norestart"',

  [int]$TimeoutSeconds = 1800,      # 30 min default; adjust per app

  [int[]]$ExpectedExitCodes = @(0, 1641, 3010),  # success, restart initiated, restart required

  [string]$MsiProperties = '',

  [string]$LogRoot = "$env:ProgramData\AppStdInstall\Logs",

  [switch]$EnforceConfig,

  [string]$EventLogName = 'Application',

  [string]$EventSource = 'AppStdInstall'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# region: utilities
function New-Directory {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -Path $Path -PathType Container)) {
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
  }
}

function Initialize-EventLog {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$LogName,
    [Parameter(Mandatory)][string]$Source
  )
  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
      # Creating a source requires admin; non-fatal if it fails.
      New-EventLog -LogName $LogName -Source $Source
    }
    return $true
  } catch {
    # Mirror failure to transcript onlydo not hard fail the run
    try { Write-Log "EventLog init failed: $($_.Exception.Message)" 'WARN' } catch { }
    return $false
  }
}

function Write-EventMirror {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Message,
    [ValidateSet('INFO','WARN','ERROR')]
    [string]$Level = 'INFO',
    [int]$EventId = 1000
  )
  try {
    if ($script:EventLogReady) {
      $entryType = switch ($Level) {
        'INFO'  { 'Information' }
        'WARN'  { 'Warning' }
        'ERROR' { 'Error' }
      }
      Write-EventLog -LogName $script:EventLogName -Source $script:EventSource -EntryType $entryType -EventId $EventId -Message $Message
    }
  } catch {
    # Swallowavoid cascading failures
  }
}

function Write-Log {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Message,
    [ValidateSet('INFO','WARN','ERROR')]
    [string]$Level = 'INFO',
    [int]$EventId = 1000
  )
  $utc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
  $line = "[$utc][$Level] $Message"

  # Fallback if $script:LogFile isn't initialized yet
  if (-not $script:LogFile) {
    try {
      $script:LogFile = Join-Path $env:TEMP 'AppStdInstall_fallback.log'
    } catch { }
  }

  Write-Verbose $line
  try { $line | Out-File -FilePath $script:LogFile -Append -Encoding UTF8 } catch { }

  # Mirror to Windows Event Log
  Write-EventMirror -Message $Message -Level $Level -EventId $EventId
}

function Get-FileNameSafe([string]$PathOrUrl) {
  try {
    if ($PathOrUrl -match '^(http|https)://') {
      return [System.IO.Path]::GetFileName((New-Object System.Uri($PathOrUrl)).AbsolutePath)
    }
    return [System.IO.Path]::GetFileName($PathOrUrl)
  } catch { return 'source' }
}

function Get-InstalledApp {
  <#
    Detect installed software by ProductCode or DisplayName via Uninstall keys.
    Returns a hashtable with keys: DisplayName, UninstallString, QuietUninstallString, ProductCode; or $null.
  #>
  param(
    [string]$ByProductCode,
    [string]$ByDisplayName
  )

  $roots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  )

  foreach ($root in $roots) {
    $keys = Get-ChildItem -Path $root -ErrorAction SilentlyContinue
    foreach ($k in $keys) {
      $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
      if (-not $p) { continue }

      $name    = $p | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
      $uninst  = $p | Select-Object -ExpandProperty UninstallString -ErrorAction SilentlyContinue
      $quninst = $p | Select-Object -ExpandProperty QuietUninstallString -ErrorAction SilentlyContinue
      $code    = $p.PSChildName

      $match = $false
      if ($ByProductCode -and $code -eq $ByProductCode) { $match = $true }
      if ($ByDisplayName -and $name -and ($name -like "*$ByDisplayName*")) { $match = $true }

      if ($match) {
        return @{
          DisplayName          = $name
          UninstallString      = $uninst
          QuietUninstallString = $quninst
          ProductCode          = $code
        }
      }
    }
  }
  return $null
}

function Invoke-Proc {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$FilePath,
    [string]$Arguments = '',
    [int[]]$ExpectedExitCodes = @(0),
    [int]$TimeoutSeconds = 1800
  )

  Write-Log -Message ("Starting process: `"{0}`" {1}" -f $FilePath, $Arguments)
  $p = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden

  # Wait with timeout
  $ok = $p.WaitForExit($TimeoutSeconds * 1000)
  if (-not $ok) {
    Write-Log -Message ("Process timeout after {0}s. Attempting graceful close..." -f $TimeoutSeconds) -Level 'WARN' -EventId 2031
    try {
      $p.CloseMainWindow() | Out-Null
      Start-Sleep -Seconds 5
    } catch { }

    if (-not $p.HasExited) {
      Write-Log -Message "Force killing process..." -Level 'WARN' -EventId 2032
      try { Stop-Process -Id $p.Id -Force } catch { }
      throw "Process timed out and was terminated."
    }
  }

  $code = $p.ExitCode
  Write-Log -Message ("Process exit code: {0}" -f $code)

  if ($ExpectedExitCodes -notcontains $code) {
    throw "Process returned unexpected exit code: $code (expected: $($ExpectedExitCodes -join ','))"
  }
  return $code
}

function Get-Source {
  <#
    Accepts local path or HTTPS URL; downloads to temp if URL.
  #>
  param([Parameter(Mandatory)][string]$Source)
  if ($Source -match '^(http|https)://') {
    $fn = Get-FileNameSafe $Source
    $dest = Join-Path -Path $env:TEMP -ChildPath $fn
    try {
      Write-Log "Downloading: $Source -> $dest"
      Invoke-WebRequest -Uri $Source -OutFile $dest -UseBasicParsing
      return $dest
    } catch {
      Write-Log "Download failed: $($_.Exception.Message)" 'ERROR' 1020
      exit 20
    }
  } else {
    if (-not (Test-Path -Path $Source -PathType Leaf)) {
      Write-Log "Source not found: $Source" 'ERROR' 1020
      exit 20
    }
    return (Resolve-Path $Source).Path
  }
}

function Test-FileSha256 {
  <#
    Computes SHA-256 and compares to expected (case-insensitive).
    Returns $true on match, $false on mismatch. Throws only on compute failure.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Expected
  )
  try {
    $hash = (Get-FileHash -Path $Path -Algorithm SHA256).Hash
    $norm = ($Expected -replace '\s','').ToUpperInvariant()
    $match = ($hash.ToUpperInvariant() -eq $norm)
    Write-Log "SHA-256 actual: $hash; expected: $norm; match: $match"
    return $match
  } catch {
    Write-Log "SHA-256 compute failed: $($_.Exception.Message)" 'ERROR' 1022
    throw
  }
}

function Install-App {
  param(
    [Parameter(Mandatory)][string]$PkgPath,
    [string]$MsiProps,
    [string]$ExeArgs
  )
  $ext = ([IO.Path]::GetExtension($PkgPath)).ToLowerInvariant()
  if ($ext -eq '.msi') {
    $msiLog = Join-Path $script:LogDir ('msi_' + (Get-FileNameSafe $PkgPath) + '.log')
    $exeArgs   = "/i `"$PkgPath`" /qn /norestart /L*v `"$msiLog`""
    if ($MsiProps) { $exeArgs = "$exeArgs $MsiProps" }
    Invoke-Proc -FilePath 'msiexec.exe' -Arguments $exeArgs `
      -ExpectedExitCodes $ExpectedExitCodes `
      -TimeoutSeconds $TimeoutSeconds | Out-Null
  } elseif ($ext -eq '.exe') {
    $exeArgs = $ExeArgs
    if (-not $exeArgs) { $exeArgs = '/S' } # fallback
    Invoke-Proc -FilePath $PkgPath -Arguments $exeArgs `
      -ExpectedExitCodes $ExpectedExitCodes `
      -TimeoutSeconds $TimeoutSeconds | Out-Null
  } else {
    throw "Unsupported installer type: $ext"
  }
}

function Uninstall-App {
  param(
    [string]$ProductCode,
    [hashtable]$Detected
  )

  if ($ProductCode) {
    $msiLog = Join-Path $script:LogDir ('msi_uninstall_' + ($ProductCode.Trim('{}')) + '.log')
    $exeArgs = "/x $ProductCode /qn /norestart /L*v `"$msiLog`""
    Invoke-Proc -FilePath 'msiexec.exe' -Arguments $exeArgs -Expected 0 | Out-Null
    return
  }

  if ($Detected -and $Detected.QuietUninstallString) {
    $cmd, $rest = $Detected.QuietUninstallString -split '\s+', 2
    Invoke-Proc -FilePath $cmd -Arguments $rest -Expected 0 | Out-Null
    return
  }

  if ($Detected -and $Detected.UninstallString) {
    if ($Detected.UninstallString -match 'msiexec\.exe.*\/I?X?\s*\{[0-9A-Fa-f\-]{36}\}') {
      $code = ($Detected.UninstallString -replace '/I', '/X') + ' /qn /norestart'
      $cmd, $rest = $code -split '\s+', 2
      Invoke-Proc -FilePath $cmd -Arguments $rest -Expected 0 | Out-Null
      return
    }
    $cmd, $rest = $Detected.UninstallString -split '\s+', 2
    Invoke-Proc -FilePath $cmd -Arguments $rest -Expected 0 | Out-Null
    return
  }

  throw "Unable to determine uninstall method."
}

function Enforce-SampleConfig {
  <#
    Example post-install config enforcement (idempotent).
    - Ensures a registry key/value exists under HKLM.
  #>
  [CmdletBinding()]
  param()
  try {
    $key = 'HKLM:\SOFTWARE\Company\StdApp'
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    New-ItemProperty -Path $key -Name 'TelemetryEnabled' -Value 0 -PropertyType DWord -Force | Out-Null
    Write-Log 'Config enforced: HKLM:\SOFTWARE\Company\StdApp\TelemetryEnabled = 0'
    return $true
  } catch {
    Write-Log "Config enforcement failed: $($_.Exception.Message)" 'ERROR' 1050
    return $false
  }
}
# endregion

# region: main
try {
  # Initialize file logging targets
  New-Directory $LogRoot
  $utcNow = [DateTime]::UtcNow
  $script:LogDir  = Join-Path $LogRoot $utcNow.ToString('yyyyMMdd')
  New-Directory $script:LogDir

  $hostName = $env:COMPUTERNAME
  $baseName = "AppStdInstall_$($Action)_$hostName" + "_$($utcNow.ToString('yyyyMMdd_HHmmssZ'))"
  $script:LogFile = Join-Path $script:LogDir ($baseName + '.log')

  # Initialize Event Log mirroring
  $script:EventLogName  = $EventLogName
  $script:EventSource   = $EventSource
  $script:EventLogReady = Initialize-EventLog -LogName $script:EventLogName -Source $script:EventSource
  if (-not $script:EventLogReady) { Write-Log -Message "Proceeding without Event Log mirroring." -Level 'WARN' -EventId 1098 }

  Write-Log -Message ("PowerShell version: {0}" -f $PSVersionTable.PSVersion.ToString())
  Write-Log -Message ("==== Begin {0} ====" -f $Action)
  Write-Log -Message ("Parameters: Source='{0}' ProductCode='{1}' DisplayName='{2}'" -f $Source, $ProductCode, $DisplayName)

  # Detection pre-check
  $detected = Get-InstalledApp -ByProductCode $ProductCode -ByDisplayName $DisplayName

  if ($Action -eq 'install') {

    if ($detected) {
      Write-Log -Message ("Already installed: {0} [{1}]" -f $detected['DisplayName'], $detected['ProductCode'])
      Write-Log -Message '==== End (idempotent) ===='
      exit 10
    }

    if (-not $Source) { Write-Log -Message 'Source is required for install.' -Level 'ERROR' -EventId 1020; exit 20 }
    $pkg = Get-Source -Source $Source

    # SHA-256 validation (optional)
    if ($ExpectedSha256) {
      try {
        $ok = Test-FileSha256 -Path $pkg -Expected $ExpectedSha256
      } catch {
        exit 22
      }
      if (-not $ok) {
        Write-Log -Message ("SHA-256 mismatch. Aborting execution of {0}" -f $pkg) -Level 'ERROR' -EventId 1021
        exit 21
      }
    } else {
      Write-Log -Message 'No ExpectedSha256 provided-skipping file integrity verification.' -Level 'WARN' -EventId 1121
    }

    try {
      Install-App -PkgPath $pkg -MsiProps $MsiProperties -ExeArgs $ExeSilentArgs
      Write-Log -Message 'Install completed.' -Level 'INFO' -EventId 1001

      if ($EnforceConfig) {
        if (-not (Enforce-SampleConfig)) { exit 50 }
      }

      # Post-detect
      $post = Get-InstalledApp -ByProductCode $ProductCode -ByDisplayName $DisplayName
      if (-not $post) { Write-Log -Message 'Post-install detection failed.' -Level 'ERROR' -EventId 1040; exit 40 }

      Write-Log -Message ("Detected after install: {0} [{1}]" -f $post['DisplayName'], $post['ProductCode'])
      Write-Log -Message '==== End (success) ===='
      exit 0

    } catch {
      Write-Log -Message ("Install failed: {0}" -f $_.Exception.Message) -Level 'ERROR' -EventId 1030
      exit 30
    }
  }

  if ($Action -eq 'uninstall') {

    if (-not $detected -and -not $ProductCode) {
      Write-Log -Message 'Nothing to uninstall (not detected).'
      Write-Log -Message '==== End (idempotent) ===='
      exit 10
    }

    try {
      Uninstall-App -ProductCode $ProductCode -Detected $detected
      Write-Log -Message 'Uninstall completed.' -Level 'INFO' -EventId 1002

      # Post-check
      $post = Get-InstalledApp -ByProductCode $ProductCode -ByDisplayName $DisplayName
      if ($post) { Write-Log -Message 'Post-uninstall detection indicates app still present.' -Level 'ERROR' -EventId 1040; exit 40 }

      Write-Log -Message '==== End (success) ===='
      exit 0

    } catch {
      Write-Log -Message ("Uninstall failed: {0}" -f $_.Exception.Message) -Level 'ERROR' -EventId 1030
      exit 30
    }
  }

} catch {
  Write-Log -Message ("Unexpected error: {0}" -f $_.Exception.Message) -Level 'ERROR' -EventId 1099
  exit 99
}
# endregion