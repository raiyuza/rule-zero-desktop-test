<#
.SYNOPSIS
  End-to-end test of the Rule Zero desktop app: silent install, self-update through GitHub Releases, quiet uninstall.

.DESCRIPTION
  Contract: docs/plans/2026-11-26-desktop-self-update.md, "End-to-end test". Windows PowerShell 5.1, no modules.

  Parameter sets:
    Update   (default)  install FromVersion from -Repo, let it update itself to ToVersion
                         (-Mode OnQuit: close the app, the installer runs on quit;
                          -Mode WhenReady: RZ_UPDATE_INSTALL_WHEN_READY=1, the app installs and relaunches by itself;
                          -Mode Both: OnQuit, then uninstall + reinstall FromVersion, then WhenReady), then uninstall.
    Tamper              install FromVersion from -Repo, point the app at -TamperRepo whose latest release
                         (-TamperVersion, newer than FromVersion) carries a deliberately wrong .sig; the app must log
                         "signature refused" and must not install it. Then uninstall.
                         GitHub cannot serve a wrong .sig in place, and the app's github provider ignores pre-releases on
                         the "latest" channel, so the tampered release must be the LATEST normal release of -TamperRepo:
                         a separate repo (recommended, e.g. raiyuza/rule-zero-desktop-test-tamper), or -Repo itself only
                         while the tampered release is its newest release (delete it afterwards). The feed check below
                         refuses to start otherwise.
    SelfTest            read-only: prints what the detection functions find on this machine (uninstall key, install
                         dir, shortcuts, protocol, updater cache, processes, log) and runs the log/sums parsers against
                         sample lines. Installs nothing, starts nothing, changes nothing. With -Repo it also reads the feed.

  Every step records named checks (PASS / FAIL / SKIP / INFO) and carries on where it makes sense. WorkDir gets
  report.json, report.md, e2e.log, the downloads and the desktop.log segment of each run. Exit 0 only when no check failed.

  It REPLACES and then REMOVES an existing Rule Zero install of the current user (the report names the version it found);
  %APPDATA%\Rule Zero (settings, saves, logs) is kept. -KeepInstalled skips the final uninstall.

.EXAMPLE
  .\e2e-update.ps1 -SelfTest
.EXAMPLE
  .\e2e-update.ps1 -Repo raiyuza/rule-zero-desktop-test -FromVersion 0.2.2 -ToVersion 0.2.3 -Mode Both
.EXAMPLE
  .\e2e-update.ps1 -TamperTest -Repo raiyuza/rule-zero-desktop-test -FromVersion 0.2.3 `
      -TamperRepo raiyuza/rule-zero-desktop-test-tamper -TamperVersion 0.2.99
#>
[CmdletBinding(DefaultParameterSetName = 'Update')]
param(
  [Parameter(Mandatory = $true, ParameterSetName = 'Update')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Tamper')]
  [Parameter(ParameterSetName = 'SelfTest')]
  [ValidatePattern('^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$')]
  [string]$Repo,

  [Parameter(Mandatory = $true, ParameterSetName = 'Update')]
  [Parameter(Mandatory = $true, ParameterSetName = 'Tamper')]
  [ValidatePattern('^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$')]
  [string]$FromVersion,

  [Parameter(Mandatory = $true, ParameterSetName = 'Update')]
  [ValidatePattern('^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$')]
  [string]$ToVersion,

  [Parameter(ParameterSetName = 'Update')]
  [ValidateSet('OnQuit', 'WhenReady', 'Both')]
  [string]$Mode = 'Both',

  [Parameter(Mandatory = $true, ParameterSetName = 'Tamper')]
  [switch]$TamperTest,

  [Parameter(Mandatory = $true, ParameterSetName = 'Tamper')]
  [ValidatePattern('^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$')]
  [string]$TamperVersion,

  # Defaults to -Repo (see the description for when that works).
  [Parameter(ParameterSetName = 'Tamper')]
  [ValidatePattern('^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$')]
  [string]$TamperRepo,

  [Parameter(Mandatory = $true, ParameterSetName = 'SelfTest')]
  [switch]$SelfTest,

  [string]$WorkDir,
  [switch]$KeepInstalled,
  # Upper bound for each long wait (an update download, an installer run).
  [ValidateRange(30, 7200)]
  [int]$TimeoutSec = 900,
  # Close a running Rule Zero instead of refusing to start.
  [switch]$Force,
  # Window style for the app the script starts (Minimized: someone may be using the PC; best effort, Electron may ignore it).
  [ValidateSet('Normal', 'Minimized')]
  [string]$WindowStyle = 'Minimized',
  [string]$ExpectedPublisher = 'Rule Zero',
  # Overrides for the log patterns below, e.g. @{ SignatureOk = '(?i)update: sig(nature)? ok' }.
  [hashtable]$Patterns = @{}
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------------------------------------------------
# Log patterns (desktop.log). TENTATIVE: written against the plan's contract ("update: " lines from src/main/updater.ts)
# and electron-updater 6.8's own logger lines; both are matched loosely. {v} is replaced by the escaped version.
# Matching is case-insensitive (PowerShell -match).
# ---------------------------------------------------------------------------------------------------------------------
$DefaultPatterns = [ordered]@{
  # main.ts: "Rule Zero desktop <version> loading <server>"
  Started          = 'Rule Zero desktop {v} loading'
  # updater.ts "update: available <v>" or electron-updater "Found version <v> (url: ...)"
  Available        = '(update:.*\bavailable\b.*{v}|Found version {v}\b)'
  # updater.ts "update: downloaded <v> ..." or electron-updater "New version <v> has been downloaded to <path>"
  Downloaded       = '(update:.*\bdownloaded\b.*{v}|New version {v} has been downloaded)'
  SignatureOk      = 'update:.*signature\b.*\b(ok|verified|valid)\b'
  # updater.ts "update: signature refused <reason>" or electron-updater's error for a non-null verifySignature result
  SignatureRefused = '(update:.*signature\b.*\brefused\b|is not signed by the application owner|ERR_UPDATER_INVALID_SIGNATURE)'
  # updater.ts "update: installing ..." or electron-updater "Auto install update on quit" / "Install: isSilent: ..."
  Installing       = '(update:.*\binstalling\b|Auto install update on quit|Install on explicit quitAndInstall|Install: isSilent)'
  # electron-updater DifferentialDownloader: "Full: 227,148.21 KB, To download: 3,312.5 KB (1%)"
  DeltaPlan        = 'Full:\s*(?<full>[\d,.]+)\s*KB,\s*To download:\s*(?<down>[\d,.]+)\s*KB'
  DeltaFallback    = '(Cannot download differentially|fallback to full download)'
  BlockMaps        = 'Download block maps'
  # updater.ts "update: downloaded ... <n> bytes ... delta|full" (the plan: "with the bytes fetched and whether it was a delta")
  AppBytes         = 'update:.*\bdownloaded\b.*?(?<bytes>\d[\d,]*)\s*(bytes|B)\b'
  AppDelta         = 'update:.*\bdownloaded\b.*\b(delta|differential)\b'
  AppFull          = 'update:.*\bdownloaded\b.*\bfull\b'
  # Anything that means the update cannot happen in this run (fail fast instead of waiting for the timeout).
  UpdateError      = '(update:.*\b(error|failed)\b|update check failed|ERR_UPDATER_|sha512 checksum mismatch)'
}
foreach ($k in @($Patterns.Keys)) { $DefaultPatterns[$k] = [string]$Patterns[$k] }
$P = $DefaultPatterns

# ---------------------------------------------------------------------------------------------------------------------
# Facts about the install (electron-builder NSIS one-click, per user; appId net.rule-zero.desktop).
# ---------------------------------------------------------------------------------------------------------------------
$AppGuid       = '9515d6f7-2db3-5a8a-9025-dcbb26e3432c'
$UninstallKey  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppGuid"
$AppKey        = "HKCU:\Software\$AppGuid"    # InstallLocation
$ProtocolKey   = 'HKCU:\Software\Classes\rulezero'
$InstallDir    = Join-Path $env:LOCALAPPDATA 'Programs\rule-zero-desktop'
$AppExeName    = 'Rule Zero.exe'
$AppExe        = Join-Path $InstallDir $AppExeName
$UserData      = Join-Path $env:APPDATA 'Rule Zero'
$DesktopLog    = Join-Path $UserData 'logs\desktop.log'
$ConfigJson    = Join-Path $UserData 'config.json'
$UpdaterCache  = Join-Path $env:LOCALAPPDATA 'rule-zero-desktop-updater'
$AppUpdateYml  = Join-Path $InstallDir 'resources\app-update.yml'
$StartMenuLnk  = Join-Path ([Environment]::GetFolderPath('Programs')) 'Rule Zero.lnk'
$DesktopLnk    = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Rule Zero.lnk'
$InstallerName = 'RuleZero-Setup-{0}.exe'

$SetName = $PSCmdlet.ParameterSetName
if (-not $TamperRepo -and $Repo) { $TamperRepo = $Repo }
if (-not $WorkDir) { $WorkDir = Join-Path $env:TEMP ('rz-e2e-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }

$script:T0 = Get-Date
$script:Checks = New-Object System.Collections.ArrayList
$script:Runs = New-Object System.Collections.ArrayList
$script:Pre = [ordered]@{}
$script:Final = [ordered]@{}
$script:Sha = @{}          # "<version>" -> sha256 of its installer (from SHA256SUMS.txt)
$script:Installer = @{}    # "<version>" -> local path of the downloaded installer
$script:LogFile = $null
$script:Touched = $false    # set once this run started an installer: only then may it uninstall

# ---------------------------------------------------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------------------------------------------------
function Write-Note([string]$Text) {
  $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $Text
  Write-Host $line
  if ($script:LogFile) { try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { } }
}

function Add-Check([string]$Name, [string]$Status, [string]$Detail = '', [double]$Seconds = -1) {
  $c = [ordered]@{
    name    = $Name
    status  = $Status
    detail  = $Detail
    seconds = $(if ($Seconds -ge 0) { [Math]::Round($Seconds, 1) } else { $null })
    at      = [Math]::Round(((Get-Date) - $script:T0).TotalSeconds, 1)
  }
  [void]$script:Checks.Add($c)
  $extra = ''
  if ($Seconds -ge 0) { $extra = ' ({0:N1} s)' -f $Seconds }
  Write-Note ('[{0}] {1}{2}{3}' -f $Status, $Name, $extra, $(if ($Detail) { ': ' + $Detail } else { '' }))
}

function Test-That([string]$Name, [bool]$Condition, [string]$Detail = '', [double]$Seconds = -1) {
  if ($Condition) { Add-Check $Name 'PASS' $Detail $Seconds } else { Add-Check $Name 'FAIL' $Detail $Seconds }
  return $Condition
}

# Runs a block; an exception becomes a FAIL check named after the step. Returns $true when nothing was thrown.
function Invoke-Step([string]$Name, [scriptblock]$Block) {
  Write-Note "== $Name"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  try {
    & $Block
    return $true
  } catch {
    $msg = $_.Exception.Message
    $where = ''
    if ($_.InvocationInfo) { $where = ' (line {0})' -f $_.InvocationInfo.ScriptLineNumber }
    Add-Check "$Name" 'FAIL' ("exception: $msg$where") $sw.Elapsed.TotalSeconds
    return $false
  }
}

function Wait-Until([int]$TimeoutSec, [scriptblock]$Condition, [int]$IntervalMs = 1000) {
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ($true) {
    if (& $Condition) { return $true }
    if ((Get-Date) -gt $deadline) { return $false }
    Start-Sleep -Milliseconds $IntervalMs
  }
}

function Expand-Pattern([string]$Name, [string]$Version = '') {
  return $P[$Name].Replace('{v}', [regex]::Escape($Version))
}

function ConvertTo-Ver([string]$V) { return [version](($V -split '-')[0]) }

# ---------------------------------------------------------------------------------------------------------------------
# Machine state
# ---------------------------------------------------------------------------------------------------------------------
function Get-RegValue([string]$Path, [string]$Name) {
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  return (Get-Item -LiteralPath $Path).GetValue($Name, $null)
}

function Get-UninstallInfo {
  if (-not (Test-Path -LiteralPath $UninstallKey)) { return $null }
  $o = [ordered]@{}
  foreach ($n in 'DisplayName', 'DisplayVersion', 'Publisher', 'QuietUninstallString', 'UninstallString', 'DisplayIcon', 'EstimatedSize', 'NoModify', 'NoRepair') {
    $o[$n] = Get-RegValue $UninstallKey $n
  }
  return $o
}

function Get-DisplayVersion {
  return [string](Get-RegValue $UninstallKey 'DisplayVersion')
}

function Get-ShortcutTarget([string]$Lnk) {
  if (-not (Test-Path -LiteralPath $Lnk)) { return $null }
  # CreateShortcut on an existing .lnk only reads it (nothing is written without .Save()).
  $sh = New-Object -ComObject WScript.Shell
  try { return $sh.CreateShortcut($Lnk).TargetPath } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($sh) }
}

function Get-ExeVersion([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  return (Get-Item -LiteralPath $Path).VersionInfo.ProductVersion
}

# electron-builder writes the product version as x.y.z.0.
function Test-ExeVersion([string]$Actual, [string]$Version) {
  if (-not $Actual) { return $false }
  return ($Actual -eq $Version -or $Actual -eq "$Version.0" -or $Actual -eq ((ConvertTo-Ver $Version).ToString() + '.0'))
}

function Test-SamePath([string]$A, [string]$B) {
  if (-not $A -or -not $B) { return $false }
  return ([IO.Path]::GetFullPath($A.Trim('"')).TrimEnd('\') -ieq [IO.Path]::GetFullPath($B.Trim('"')).TrimEnd('\'))
}

function Test-UnderDir([string]$Path, [string]$Dir) {
  if (-not $Path) { return $false }
  return [IO.Path]::GetFullPath($Path).StartsWith(([IO.Path]::GetFullPath($Dir).TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)
}

# Every "Rule Zero.exe" process (main, GPU, renderers...), wherever it runs from.
function Get-AppProcesses {
  return @(Get-CimInstance Win32_Process -Filter "Name='$AppExeName'" -ErrorAction SilentlyContinue)
}

# Electron's main (browser) process: the one without --type= on its command line.
function Get-AppMainProcesses {
  return @(Get-AppProcesses | Where-Object { -not $_.CommandLine -or $_.CommandLine -notmatch '--type=' })
}

function Get-EngineProcesses {
  return @(Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" -ErrorAction SilentlyContinue |
    Where-Object { Test-UnderDir $_.ExecutablePath $InstallDir })
}

# NSIS installer / uninstaller processes (the uninstaller re-runs itself from %TEMP% as Un_A.exe).
function Get-InstallerProcesses {
  return @(Get-CimInstance Win32_Process -Filter "Name LIKE 'RuleZero-Setup%' OR Name LIKE 'Uninstall Rule Zero%' OR Name='Un_A.exe' OR Name='Au_.exe'" -ErrorAction SilentlyContinue)
}

function Format-Procs($Procs) {
  $p = @($Procs | Where-Object { $null -ne $_ })
  if ($p.Count -eq 0) { return 'none' }
  return (($p | ForEach-Object { '{0} pid {1} {2}' -f $_.Name, $_.ProcessId, $_.ExecutablePath }) -join '; ')
}

function Get-InstallState {
  $u = Get-UninstallInfo
  $cacheFiles = @()
  if (Test-Path -LiteralPath $UpdaterCache) {
    $cacheFiles = @(Get-ChildItem -LiteralPath $UpdaterCache -Recurse -File -ErrorAction SilentlyContinue |
      ForEach-Object { '{0} ({1} bytes)' -f $_.FullName.Substring($UpdaterCache.Length + 1), $_.Length })
  }
  return [ordered]@{
    uninstallKey        = $(if ($u) { $u } else { $null })
    installDirExists    = (Test-Path -LiteralPath $InstallDir)
    exeVersion          = (Get-ExeVersion $AppExe)
    startMenuLnk        = (Get-ShortcutTarget $StartMenuLnk)
    desktopLnk          = (Get-ShortcutTarget $DesktopLnk)
    protocolKeyExists   = (Test-Path -LiteralPath $ProtocolKey)
    protocolCommand     = (Get-RegValue "$ProtocolKey\shell\open\command" '')
    protocolDefaultIcon = (Get-RegValue "$ProtocolKey\DefaultIcon" '')
    installLocation     = (Get-RegValue $AppKey 'InstallLocation')
    appUpdateYml        = $(if (Test-Path -LiteralPath $AppUpdateYml) { ((Get-Content -LiteralPath $AppUpdateYml) -join ' ; ') } else { $null })
    updaterCacheFiles   = $cacheFiles
    userDataExists      = (Test-Path -LiteralPath $UserData)
    desktopLogBytes     = $(if (Test-Path -LiteralPath $DesktopLog) { (Get-Item -LiteralPath $DesktopLog).Length } else { $null })
    configJson          = $(if (Test-Path -LiteralPath $ConfigJson) { (Get-Content -LiteralPath $ConfigJson -Raw) } else { $null })
    appProcesses        = (Format-Procs (Get-AppProcesses))
    engineProcesses     = (Format-Procs (Get-EngineProcesses))
    installerProcesses  = (Format-Procs (Get-InstallerProcesses))
  }
}

function Split-CommandLine([string]$Cmd) {
  $m = [regex]::Match($Cmd, '^\s*"(?<exe>[^"]+)"\s*(?<args>.*)$')
  if (-not $m.Success) { $m = [regex]::Match($Cmd, '^\s*(?<exe>\S+)\s*(?<args>.*)$') }
  if (-not $m.Success) { return $null }
  return @{ exe = $m.Groups['exe'].Value; args = $m.Groups['args'].Value.Trim() }
}

# ---------------------------------------------------------------------------------------------------------------------
# desktop.log tailing (the app appends with appendFileSync; it renames the file to .1 at start when it is over 5 MB)
# ---------------------------------------------------------------------------------------------------------------------
function New-LogTail([string]$Path) {
  $len = [long]0
  if (Test-Path -LiteralPath $Path) { $len = (Get-Item -LiteralPath $Path).Length }
  return [pscustomobject]@{ Path = $Path; Offset = $len; Lines = (New-Object System.Collections.ArrayList) }
}

function Update-LogTail($Tail) {
  $new = New-Object System.Collections.ArrayList
  if (-not (Test-Path -LiteralPath $Tail.Path)) { return ,$new }
  $fs = [IO.File]::Open($Tail.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
  try {
    if ($fs.Length -lt $Tail.Offset) { $Tail.Offset = [long]0 }   # rotated
    $avail = $fs.Length - $Tail.Offset
    if ($avail -le 0) { return ,$new }
    $count = [int][Math]::Min($avail, 16MB)
    $buf = New-Object byte[] $count
    $fs.Position = $Tail.Offset
    $read = 0
    while ($read -lt $count) {
      $n = $fs.Read($buf, $read, $count - $read)
      if ($n -le 0) { break }
      $read += $n
    }
    if ($read -le 0) { return ,$new }
    $last = [Array]::LastIndexOf($buf, [byte]10, $read - 1)
    if ($last -lt 0) { return ,$new }                              # no complete line yet
    $text = [Text.Encoding]::UTF8.GetString($buf, 0, $last + 1)
    $Tail.Offset += ($last + 1)
    foreach ($l in ($text -split "`r?`n")) {
      $c = $l.Replace([string][char]0, '').Trim()
      if ($c) { [void]$Tail.Lines.Add($c); [void]$new.Add($c) }
    }
  } finally {
    $fs.Dispose()
  }
  return ,$new
}

# Waits until every $Want pattern matched a new line, a $FailOn pattern matched, the process exited or the timeout passed.
function Wait-LogEvents($Tail, [hashtable]$Want, [hashtable]$FailOn = @{}, [int]$TimeoutSec = 600, [int]$ProcessId = 0) {
  $r = @{ Found = @{}; Failed = $null; FailedLine = $null; TimedOut = $false; Exited = $false }
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ($true) {
    $exited = $false
    if ($ProcessId -gt 0 -and -not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) { $exited = $true }
    foreach ($line in (Update-LogTail $Tail)) {
      foreach ($k in @($Want.Keys)) {
        if (-not $r.Found.ContainsKey($k) -and $line -match $Want[$k]) { $r.Found[$k] = $line }
      }
      foreach ($k in @($FailOn.Keys)) {
        if ($null -eq $r.Failed -and $line -match $FailOn[$k]) { $r.Failed = $k; $r.FailedLine = $line }
      }
    }
    if ($null -ne $r.Failed) { break }
    if ($r.Found.Count -eq $Want.Count) { break }
    if ($exited) { $r.Exited = $true; break }
    if ((Get-Date) -gt $deadline) { $r.TimedOut = $true; break }
    Start-Sleep -Milliseconds 1000
  }
  return $r
}

function Find-Line($Lines, [string]$Pattern) {
  foreach ($l in @($Lines)) { if ($l -match $Pattern) { return $l } }
  return $null
}

function ConvertFrom-Kb([string]$S) {
  return [long]([double]::Parse(($S -replace ',', ''), [Globalization.CultureInfo]::InvariantCulture) * 1024)
}

# What the download was: delta (blockmap) or full, and how many bytes, from electron-updater's and the app's lines.
function Get-DeltaInfo($Lines) {
  $i = [ordered]@{
    delta = $null; newFileBytes = $null; downloadBytes = $null; percent = $null
    blockMapsLine = $false; fallback = $false; fallbackLine = $null; appBytes = $null; appSaysDelta = $null; source = $null
  }
  foreach ($l in @($Lines)) {
    $m = [regex]::Match($l, $P.DeltaPlan)
    if ($m.Success) {
      $i.newFileBytes = ConvertFrom-Kb $m.Groups['full'].Value
      $i.downloadBytes = ConvertFrom-Kb $m.Groups['down'].Value
      if ($i.newFileBytes -gt 0) { $i.percent = [Math]::Round(100.0 * $i.downloadBytes / $i.newFileBytes, 2) }
    }
    if ($l -match $P.BlockMaps) { $i.blockMapsLine = $true }
    if ($l -match $P.DeltaFallback) { $i.fallback = $true; $i.fallbackLine = $l }
    $a = [regex]::Match($l, $P.AppBytes, 'IgnoreCase')
    if ($a.Success) { $i.appBytes = [long]($a.Groups['bytes'].Value -replace ',', '') }
    if ($l -match $P.AppDelta) { $i.appSaysDelta = $true } elseif ($l -match $P.AppFull) { $i.appSaysDelta = $false }
  }
  if ($null -ne $i.downloadBytes) {
    $i.delta = -not $i.fallback
    $i.source = 'electron-updater "Full: .. To download: .." line'
  } elseif ($null -ne $i.appSaysDelta) {
    $i.delta = $i.appSaysDelta -and -not $i.fallback
    $i.source = 'app "update: downloaded" line'
  } elseif ($i.fallback) {
    $i.delta = $false
    $i.source = 'fallback line'
  }
  return $i
}

# ---------------------------------------------------------------------------------------------------------------------
# Feed
# ---------------------------------------------------------------------------------------------------------------------
function New-WebClient {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $wc = New-Object Net.WebClient
  $wc.Headers.Add('User-Agent', 'rz-desktop-e2e')
  return $wc
}

function Get-ReleaseUrl([string]$R, [string]$Version, [string]$File) {
  return 'https://github.com/{0}/releases/download/v{1}/{2}' -f $R, $Version, $File
}

function Get-RemoteText([string]$Url) {
  $wc = New-WebClient
  try { return $wc.DownloadString($Url) }
  catch { throw ("GET {0}: {1}" -f $Url, $_.Exception.InnerException.Message) }
  finally { $wc.Dispose() }
}

function Save-RemoteFile([string]$Url, [string]$Dest) {
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Dest) | Out-Null
  $wc = New-WebClient
  try { $wc.DownloadFile($Url, $Dest) }
  catch { throw ("GET {0}: {1}" -f $Url, $_.Exception.InnerException.Message) }
  finally { $wc.Dispose() }
}

function Read-Sha256Sums([string]$Text) {
  $h = @{}
  foreach ($l in ($Text -split "`r?`n")) {
    $m = [regex]::Match($l, '^\s*(?<h>[0-9a-fA-F]{64})\s+\*?(?<f>\S.*?)\s*$')
    if ($m.Success) { $h[$m.Groups['f'].Value] = $m.Groups['h'].Value.ToLowerInvariant() }
  }
  return $h
}

function Get-YmlVersion([string]$Text) {
  $m = [regex]::Match($Text, '(?m)^version:\s*["'']?(?<v>[^"''\s]+)')
  if ($m.Success) { return $m.Groups['v'].Value }
  return $null
}

function Get-Sha256([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

# Downloads RuleZero-Setup-<v>.exe of a release and checks it against that release's SHA256SUMS.txt.
function Get-Installer([string]$R, [string]$Version) {
  $file = $InstallerName -f $Version
  $dir = Join-Path $WorkDir ("download\v$Version")
  $sums = Read-Sha256Sums (Get-RemoteText (Get-ReleaseUrl $R $Version 'SHA256SUMS.txt'))
  if (-not $sums.ContainsKey($file)) { throw "SHA256SUMS.txt of v$Version has no line for $file" }
  $script:Sha[$Version] = $sums[$file]
  $dest = Join-Path $dir $file
  $sw = [Diagnostics.Stopwatch]::StartNew()
  Save-RemoteFile (Get-ReleaseUrl $R $Version $file) $dest
  $len = (Get-Item -LiteralPath $dest).Length
  $actual = Get-Sha256 $dest
  $ok = Test-That "download $file matches SHA256SUMS.txt" ($actual -eq $sums[$file]) ("{0} bytes, sha256 {1}" -f $len, $actual) $sw.Elapsed.TotalSeconds
  if ($ok) { $script:Installer[$Version] = $dest }
}

# The update the app will see: the latest (non pre-release) release's latest.yml must name $Version.
function Test-Feed([string]$R, [string]$Version, [string]$Label) {
  $yml = Get-RemoteText ('https://github.com/{0}/releases/latest/download/latest.yml' -f $R)
  $v = Get-YmlVersion $yml
  [void](Test-That "$Label`: latest release of $R is v$Version" ($v -eq $Version) ("latest.yml says version $v"))
  $sig = Get-RemoteText (Get-ReleaseUrl $R $Version (($InstallerName -f $Version) + '.sig'))
  Add-Check "$Label`: .sig of v$Version" 'INFO' ($sig.Trim())
}

# ---------------------------------------------------------------------------------------------------------------------
# App and installer actions
# ---------------------------------------------------------------------------------------------------------------------
function Start-App([hashtable]$Env) {
  # Process environment is inherited: set ours, drop every other RZ_* (and so RZ_AUTO_UPDATE), restore afterwards.
  $saved = @{}
  foreach ($e in @(Get-ChildItem Env: | Where-Object { $_.Name -like 'RZ_*' })) { $saved[$e.Name] = $e.Value; Remove-Item -LiteralPath ("Env:" + $e.Name) }
  try {
    foreach ($k in $Env.Keys) { Set-Item -LiteralPath ("Env:" + $k) -Value $Env[$k] }
    $p = Start-Process -FilePath $AppExe -WorkingDirectory $InstallDir -WindowStyle $WindowStyle -PassThru
    $null = $p.Handle
    return $p
  } finally {
    foreach ($k in $Env.Keys) { Remove-Item -LiteralPath ("Env:" + $k) -ErrorAction SilentlyContinue }
    foreach ($k in $saved.Keys) { Set-Item -LiteralPath ("Env:" + $k) -Value $saved[$k] }
  }
}

# CloseMainWindow (WM_CLOSE, no focus change); after $TimeoutSec a hard kill of every app process.
function Stop-AppGracefully([int]$ProcessId, [int]$TimeoutSec = 60) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
  if (-not $p) { return @{ Graceful = $true; Seconds = 0; Detail = 'already exited' } }
  $lastSend = -100.0
  $sent = 0
  while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
    $p.Refresh()
    if ($p.HasExited) { break }
    if (($sw.Elapsed.TotalSeconds - $lastSend) -ge 15 -and $p.MainWindowHandle -ne [IntPtr]::Zero) {
      if ($p.CloseMainWindow()) { $sent++ }
      $lastSend = $sw.Elapsed.TotalSeconds
    }
    Start-Sleep -Milliseconds 500
  }
  $p.Refresh()
  if ($p.HasExited) {
    [void](Wait-Until 20 { @(Get-AppProcesses).Count -eq 0 })
    return @{ Graceful = $true; Seconds = $sw.Elapsed.TotalSeconds; Detail = ("exited after {0:N1} s, {1} close message(s)" -f $sw.Elapsed.TotalSeconds, $sent) }
  }
  foreach ($x in (Get-AppProcesses)) { Stop-Process -Id $x.ProcessId -Force -ErrorAction SilentlyContinue }
  return @{ Graceful = $false; Seconds = $sw.Elapsed.TotalSeconds; Detail = ("still running after {0} s ({1} close message(s), window handle {2}); killed" -f $TimeoutSec, $sent, $p.MainWindowHandle) }
}

function Stop-AnyApp([string]$Label) {
  foreach ($m in (Get-AppMainProcesses)) {
    $s = Stop-AppGracefully $m.ProcessId 60
    Add-Check "$Label`: closed running app pid $($m.ProcessId)" $(if ($s.Graceful) { 'INFO' } else { 'FAIL' }) $s.Detail
  }
}

function Install-RZ([string]$Version, [string]$Label) {
  if (-not $script:Installer.ContainsKey($Version)) { Add-Check "$Label" 'SKIP' "no verified $Version installer"; return $false }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $script:Touched = $true
  $p = Start-Process -FilePath $script:Installer[$Version] -ArgumentList '/S' -PassThru
  $null = $p.Handle
  $exited = $p.WaitForExit($TimeoutSec * 1000)
  $code = $(if ($exited) { $p.ExitCode } else { 'still running' })
  [void](Test-That "$Label`: installer /S exits 0" ($exited -and $p.ExitCode -eq 0) ("exit code $code") $sw.Elapsed.TotalSeconds)
  $reg = Wait-Until 60 { (Get-DisplayVersion) -eq $Version -and @(Get-InstallerProcesses).Count -eq 0 }
  [void](Test-That "$Label`: registered as $Version" $reg ("DisplayVersion " + (Get-DisplayVersion)) $sw.Elapsed.TotalSeconds)
  # A silent install should not start the app (electron-builder runs it after a silent install only with --force-run).
  $started = Wait-Until 5 { @(Get-AppMainProcesses).Count -gt 0 }
  [void](Test-That "$Label`: silent install does not start the app" (-not $started) (Format-Procs (Get-AppMainProcesses)))
  if ($started) { Stop-AnyApp $Label }
  Test-InstallState $Version $Label
  return $reg
}

function Test-InstallState([string]$Version, [string]$Label) {
  $u = Get-UninstallInfo
  if (-not $u) { Add-Check "$Label`: uninstall key" 'FAIL' "missing: $UninstallKey"; return }
  [void](Test-That "$Label`: DisplayVersion = $Version" ($u.DisplayVersion -eq $Version) ([string]$u.DisplayVersion))
  # New builds say "Rule Zero"; 0.2.1 said "Rule Zero 0.2.1".
  [void](Test-That "$Label`: DisplayName" ($u.DisplayName -eq 'Rule Zero' -or $u.DisplayName -eq "Rule Zero $Version") ([string]$u.DisplayName))
  [void](Test-That "$Label`: Publisher = $ExpectedPublisher" ($u.Publisher -eq $ExpectedPublisher) ([string]$u.Publisher))
  [void](Test-That "$Label`: DisplayIcon = exe,0" ($u.DisplayIcon -ieq "$AppExe,0") ([string]$u.DisplayIcon))
  [void](Test-That "$Label`: NoModify 1, NoRepair 1, EstimatedSize" ($u.NoModify -eq 1 -and $u.NoRepair -eq 1 -and $null -ne $u.EstimatedSize) ("NoModify {0}, NoRepair {1}, EstimatedSize {2}" -f $u.NoModify, $u.NoRepair, $u.EstimatedSize))
  $q = [string]$u.QuietUninstallString
  $qs = Split-CommandLine $q
  $qok = $qs -and (Test-SamePath $qs.exe (Join-Path $InstallDir 'Uninstall Rule Zero.exe')) -and (Test-Path -LiteralPath $qs.exe) -and ($qs.args -eq '/currentuser /S')
  [void](Test-That "$Label`: QuietUninstallString = <inst>\Uninstall Rule Zero.exe /currentuser /S" $qok $q)
  $il = [string](Get-RegValue $AppKey 'InstallLocation')
  [void](Test-That "$Label`: HKCU\Software\<guid> InstallLocation = install dir" (Test-SamePath $il $InstallDir) $il)
  $ev = Get-ExeVersion $AppExe
  [void](Test-That "$Label`: $AppExeName in install dir, version $Version" (Test-ExeVersion $ev $Version) ("$AppExe product version $ev"))
  $sm = Get-ShortcutTarget $StartMenuLnk
  [void](Test-That "$Label`: Start menu shortcut -> exe" (Test-SamePath $sm $AppExe) ("$StartMenuLnk -> $sm"))
  $dl = Get-ShortcutTarget $DesktopLnk
  [void](Test-That "$Label`: desktop shortcut -> exe" (Test-SamePath $dl $AppExe) ("$DesktopLnk -> $dl"))
  $cmd = [string](Get-RegValue "$ProtocolKey\shell\open\command" '')
  $pdef = Get-RegValue $ProtocolKey ''
  $purl = Get-RegValue $ProtocolKey 'URL Protocol'
  $picon = [string](Get-RegValue "$ProtocolKey\DefaultIcon" '')
  $pok = ($pdef -eq 'URL:rulezero') -and ($null -ne $purl) -and ($cmd -ieq ('"{0}" "%1"' -f $AppExe))
  [void](Test-That "$Label`: rulezero:// protocol -> exe" $pok ("(Default) '$pdef', URL Protocol '$purl', command: $cmd"))
  [void](Test-That "$Label`: rulezero DefaultIcon = exe,0" ($picon -ieq "$AppExe,0") $picon)
  if (Test-Path -LiteralPath $AppUpdateYml) {
    $y = Get-Content -LiteralPath $AppUpdateYml -Raw
    $own = [regex]::Match($y, '(?m)^owner:\s*(\S+)').Groups[1].Value
    $rpo = [regex]::Match($y, '(?m)^repo:\s*(\S+)').Groups[1].Value
    [void](Test-That "$Label`: resources\app-update.yml names the build-time repo" ([bool]$own -and [bool]$rpo) ("$own/$rpo"))
  } else {
    Add-Check "$Label`: resources\app-update.yml names the build-time repo" 'FAIL' "missing: $AppUpdateYml"
  }
  $inst = Join-Path $UpdaterCache 'installer.exe'
  if (-not (Test-Path -LiteralPath $inst)) {
    Add-Check "$Label`: updater cache installer.exe (delta base)" 'FAIL' "missing: $inst"
  } elseif ($script:Sha.ContainsKey($Version)) {
    $h = Get-Sha256 $inst
    [void](Test-That "$Label`: updater cache installer.exe is the $Version installer (delta base)" ($h -eq $script:Sha[$Version]) ("sha256 $h, expected " + $script:Sha[$Version]))
  } else {
    Add-Check "$Label`: updater cache installer.exe (delta base)" 'PASS' ("{0} bytes, sha256 not known for $Version" -f (Get-Item -LiteralPath $inst).Length)
  }
}

function Uninstall-RZ([string]$Label) {
  $u = Get-UninstallInfo
  if (-not $u -or -not $u.QuietUninstallString) { Add-Check "$Label`: quiet uninstall" 'FAIL' 'no uninstall key / QuietUninstallString'; return }
  Stop-AnyApp $Label
  $cmd = Split-CommandLine ([string]$u.QuietUninstallString)
  $sw = [Diagnostics.Stopwatch]::StartNew()
  if ($cmd.args) { $p = Start-Process -FilePath $cmd.exe -ArgumentList $cmd.args -PassThru }
  else { $p = Start-Process -FilePath $cmd.exe -PassThru }
  $null = $p.Handle
  [void]$p.WaitForExit($TimeoutSec * 1000)
  # The NSIS uninstaller re-runs itself from %TEMP% and the first process exits at once: wait for the result instead.
  $done = Wait-Until 300 { -not (Test-Path -LiteralPath $UninstallKey) -and -not (Test-Path -LiteralPath $AppExe) -and @(Get-InstallerProcesses).Count -eq 0 }
  [void](Test-That "$Label`: quiet uninstall finished" $done ("{0} {1}; exit code {2}" -f $cmd.exe, $cmd.args, $(if ($p.HasExited) { $p.ExitCode } else { 'running' })) $sw.Elapsed.TotalSeconds)
  [void](Wait-Until 30 { -not (Test-Path -LiteralPath $InstallDir) })
}

function Test-Uninstalled([string]$Label) {
  [void](Test-That "$Label`: uninstall key gone" (-not (Test-Path -LiteralPath $UninstallKey)) $UninstallKey)
  [void](Test-That "$Label`: HKCU\Software\<guid> gone" (-not (Test-Path -LiteralPath $AppKey)) $AppKey)
  $left = ''
  if (Test-Path -LiteralPath $InstallDir) { $left = (@(Get-ChildItem -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 5 | ForEach-Object { $_.FullName }) -join '; ') }
  [void](Test-That "$Label`: install dir gone" (-not (Test-Path -LiteralPath $InstallDir)) ("$InstallDir $left"))
  [void](Test-That "$Label`: Start menu shortcut gone" (-not (Test-Path -LiteralPath $StartMenuLnk)) $StartMenuLnk)
  [void](Test-That "$Label`: desktop shortcut gone" (-not (Test-Path -LiteralPath $DesktopLnk)) $DesktopLnk)
  [void](Test-That "$Label`: rulezero protocol key gone" (-not (Test-Path -LiteralPath $ProtocolKey)) $ProtocolKey)
  [void](Test-That "$Label`: updater cache gone" (-not (Test-Path -LiteralPath $UpdaterCache)) $UpdaterCache)
  [void](Test-That "$Label`: %APPDATA%\Rule Zero kept" ((Test-Path -LiteralPath $UserData) -and (Test-Path -LiteralPath $DesktopLog)) $UserData)
  [void](Test-That "$Label`: no app or engine process left" (@(Get-AppProcesses).Count -eq 0 -and @(Get-EngineProcesses).Count -eq 0) ((Format-Procs (Get-AppProcesses)) + ' / ' + (Format-Procs (Get-EngineProcesses))))
}

function Save-LogSegment($Tail, [string]$Name) {
  [void](Update-LogTail $Tail)
  $f = Join-Path $WorkDir ("desktop-$Name.log")
  Set-Content -LiteralPath $f -Value @($Tail.Lines) -Encoding UTF8
  return $f
}

# ---------------------------------------------------------------------------------------------------------------------
# Runs
# ---------------------------------------------------------------------------------------------------------------------
function Invoke-UpdateRun([string]$RunMode) {
  $L = "update $RunMode"
  $run = [ordered]@{ mode = $RunMode; from = $FromVersion; to = $ToVersion; downloadSeconds = $null; installSeconds = $null; download = $null; log = $null }
  [void]$script:Runs.Add($run)
  $have = Get-DisplayVersion
  if ($have -ne $FromVersion) { Add-Check "$L`: run" 'SKIP' "installed version is '$have', not $FromVersion"; return }
  if (-not (Test-Path -LiteralPath $AppExe)) { Add-Check "$L`: run" 'SKIP' "no $AppExe"; return }

  $tail = New-LogTail $DesktopLog
  $envs = @{ RZ_ENGINE = '0'; RZ_UPDATE_REPO = $Repo }
  if ($RunMode -eq 'WhenReady') { $envs['RZ_UPDATE_INSTALL_WHEN_READY'] = '1' }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $proc = Start-App $envs
  Add-Check "$L`: app started" 'INFO' ("pid {0}, env {1}" -f $proc.Id, (($envs.Keys | Sort-Object | ForEach-Object { "$_=$($envs[$_])" }) -join ' '))

  $want = @{
    started     = (Expand-Pattern 'Started' $FromVersion)
    available   = (Expand-Pattern 'Available' $ToVersion)
    signatureOk = (Expand-Pattern 'SignatureOk')
    downloaded  = (Expand-Pattern 'Downloaded' $ToVersion)
  }
  $fail = @{ refused = (Expand-Pattern 'SignatureRefused'); error = (Expand-Pattern 'UpdateError') }
  $r = Wait-LogEvents $tail $want $fail $TimeoutSec $proc.Id
  $run.downloadSeconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
  $why = ''
  if ($r.Failed) { $why = " (stopped on $($r.Failed): $($r.FailedLine))" }
  elseif ($r.TimedOut) { $why = " (timeout $TimeoutSec s)" }
  elseif ($r.Exited -and $r.Found.Count -lt $want.Count) { $why = ' (app exited)' }
  foreach ($k in 'started', 'available', 'signatureOk', 'downloaded') {
    $line = $null
    if ($r.Found.ContainsKey($k)) { $line = $r.Found[$k] }
    [void](Test-That "$L`: log '$k'" ($null -ne $line) ($(if ($line) { $line } else { "not seen$why" })))
  }
  $d = Get-DeltaInfo $tail.Lines
  $run.download = $d
  $dd = 'delta {0}; {1} of {2} bytes ({3}%); app says {4} bytes; source: {5}{6}' -f $d.delta, $d.downloadBytes, $d.newFileBytes, $d.percent, $d.appBytes, $d.source, $(if ($d.fallback) { '; FALLBACK: ' + $d.fallbackLine } else { '' })
  [void](Test-That "$L`: downloaded as a delta" ($d.delta -eq $true) $dd $run.downloadSeconds)

  $sw2 = [Diagnostics.Stopwatch]::StartNew()
  if ($RunMode -eq 'OnQuit') {
    if ($r.Exited) {
      Add-Check "$L`: app closes gracefully" 'FAIL' 'the app exited before it was asked to'
    } else {
      $s = Stop-AppGracefully $proc.Id 60
      [void](Test-That "$L`: app closes gracefully within 60 s" $s.Graceful $s.Detail $s.Seconds)
    }
  } else {
    $quit = Wait-Until 180 { $proc.HasExited }
    [void](Test-That "$L`: app quits by itself to install" $quit ("pid {0} {1}" -f $proc.Id, $(if ($quit) { 'exited' } else { 'still running after 180 s' })) $sw2.Elapsed.TotalSeconds)
    if (-not $quit) { [void](Stop-AppGracefully $proc.Id 30) }
  }
  [void](Update-LogTail $tail)
  $inst = Find-Line $tail.Lines (Expand-Pattern 'Installing')
  [void](Test-That "$L`: log 'installing'" ($null -ne $inst) ($(if ($inst) { $inst } else { 'not seen' })))

  $installed = Wait-Until $TimeoutSec { (Get-DisplayVersion) -eq $ToVersion -and @(Get-InstallerProcesses).Count -eq 0 }
  $run.installSeconds = [Math]::Round($sw2.Elapsed.TotalSeconds, 1)
  [void](Test-That "$L`: installer finished, DisplayVersion = $ToVersion" $installed ("DisplayVersion " + (Get-DisplayVersion) + "; installers: " + (Format-Procs (Get-InstallerProcesses))) $run.installSeconds)

  if ($RunMode -eq 'WhenReady') {
    $script:relaunched = $null
    $back = Wait-Until 180 {
      $m = @(Get-AppMainProcesses | Where-Object { $_.ProcessId -ne $proc.Id -and (Test-SamePath $_.ExecutablePath $AppExe) })
      if ($m.Count -gt 0) { $script:relaunched = $m[0]; return $true }
      return $false
    }
    $rv = Get-ExeVersion $AppExe
    [void](Test-That "$L`: relaunched on $ToVersion" ($back -and (Test-ExeVersion $rv $ToVersion)) ($(if ($back) { "pid $($script:relaunched.ProcessId), exe version $rv, command line: $($script:relaunched.CommandLine)" } else { 'no new app process within 180 s' })) $sw2.Elapsed.TotalSeconds)
    if ($back) { [void](Test-That "$L`: relaunch carries --updated" ([string]$script:relaunched.CommandLine -match '(^|\s)--updated(\s|$)') ([string]$script:relaunched.CommandLine)) }
    $r2 = Wait-LogEvents $tail @{ started = (Expand-Pattern 'Started' $ToVersion) } @{} 90 0
    [void](Test-That "$L`: log 'started' for $ToVersion" ($r2.Found.ContainsKey('started')) ($(if ($r2.Found.ContainsKey('started')) { $r2.Found['started'] } else { 'not seen within 90 s' })))
    if ($back) {
      $s = Stop-AppGracefully $script:relaunched.ProcessId 60
      [void](Test-That "$L`: relaunched app closes gracefully within 60 s" $s.Graceful $s.Detail $s.Seconds)
    }
  }

  $clean = Wait-Until 30 { @(Get-AppProcesses).Count -eq 0 -and @(Get-EngineProcesses).Count -eq 0 }
  [void](Test-That "$L`: no app or engine process left" $clean ((Format-Procs (Get-AppProcesses)) + ' / ' + (Format-Procs (Get-EngineProcesses))))
  Test-InstallState $ToVersion "$L`: after"
  $run.log = Save-LogSegment $tail $RunMode
}

function Invoke-TamperRun {
  $L = 'tamper'
  $run = [ordered]@{ mode = 'Tamper'; from = $FromVersion; to = $TamperVersion; repo = $TamperRepo; downloadSeconds = $null; download = $null; log = $null }
  [void]$script:Runs.Add($run)
  $have = Get-DisplayVersion
  if ($have -ne $FromVersion) { Add-Check "$L`: run" 'SKIP' "installed version is '$have', not $FromVersion"; return }
  $tail = New-LogTail $DesktopLog
  # INSTALL_WHEN_READY makes a broken check visible at once: the app would install the tampered build right away.
  $envs = @{ RZ_ENGINE = '0'; RZ_UPDATE_REPO = $TamperRepo; RZ_UPDATE_INSTALL_WHEN_READY = '1' }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $proc = Start-App $envs
  Add-Check "$L`: app started" 'INFO' ("pid {0}, RZ_UPDATE_REPO={1}" -f $proc.Id, $TamperRepo)
  $r = Wait-LogEvents $tail @{ refused = (Expand-Pattern 'SignatureRefused') } @{ downloaded = (Expand-Pattern 'Downloaded' $TamperVersion); signatureOk = (Expand-Pattern 'SignatureOk') } $TimeoutSec $proc.Id
  $run.downloadSeconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
  $av = Find-Line $tail.Lines (Expand-Pattern 'Available' $TamperVersion)
  [void](Test-That "$L`: log 'available' $TamperVersion" ($null -ne $av) ($(if ($av) { $av } else { 'not seen' })))
  $detail = 'not seen'
  if ($r.Found.ContainsKey('refused')) { $detail = $r.Found['refused'] }
  elseif ($r.Failed) { $detail = "ACCEPTED: $($r.FailedLine)" }
  elseif ($r.TimedOut) { $detail = "not seen within $TimeoutSec s" }
  elseif ($r.Exited) { $detail = 'app exited first' }
  [void](Test-That "$L`: log 'signature refused'" ($r.Found.ContainsKey('refused')) $detail $run.downloadSeconds)
  $run.download = Get-DeltaInfo $tail.Lines

  # Give a (broken) install-when-ready 20 s to show itself.
  $sw2 = [Diagnostics.Stopwatch]::StartNew()
  $installerSeen = $false
  while ($sw2.Elapsed.TotalSeconds -lt 20) {
    if (@(Get-InstallerProcesses).Count -gt 0) { $installerSeen = $true }
    Start-Sleep -Milliseconds 500
  }
  [void](Test-That "$L`: app keeps running, no installer started" ((-not $proc.HasExited) -and -not $installerSeen) ("app exited: {0}; installer seen: {1}" -f $proc.HasExited, $installerSeen))
  $s = Stop-AppGracefully $proc.Id 60
  [void](Test-That "$L`: app closes gracefully within 60 s" $s.Graceful $s.Detail $s.Seconds)
  # Nothing may install on quit either.
  $sw3 = [Diagnostics.Stopwatch]::StartNew()
  while ($sw3.Elapsed.TotalSeconds -lt 30) {
    if (@(Get-InstallerProcesses).Count -gt 0) { $installerSeen = $true }
    Start-Sleep -Milliseconds 500
  }
  [void](Wait-Until 120 { @(Get-InstallerProcesses).Count -eq 0 })
  [void](Test-That "$L`: no installer ran on quit" (-not $installerSeen) ("installer seen: $installerSeen"))
  [void](Test-That "$L`: DisplayVersion unchanged ($FromVersion)" ((Get-DisplayVersion) -eq $FromVersion -and (Test-ExeVersion (Get-ExeVersion $AppExe) $FromVersion)) ("DisplayVersion {0}, exe {1}" -f (Get-DisplayVersion), (Get-ExeVersion $AppExe)))
  $pend = Join-Path $UpdaterCache ('pending\' + ($InstallerName -f $TamperVersion))
  [void](Test-That "$L`: refused installer not kept in the cache" (-not (Test-Path -LiteralPath $pend)) $pend)
  $run.log = Save-LogSegment $tail 'tamper'
}

function Invoke-Preflight {
  $u = Get-UninstallInfo
  $script:Pre.installedVersion = $(if ($u) { [string]$u.DisplayVersion } else { $null })
  $script:Pre.state = Get-InstallState
  Add-Check 'preflight: existing install (will be replaced)' 'INFO' ($(if ($u) { "Rule Zero $($u.DisplayVersion) at $InstallDir" } else { 'none' }))
  $apps = Get-AppProcesses
  if (@($apps).Count -gt 0) {
    if (-not $Force) {
      Add-Check 'preflight: no Rule Zero running' 'FAIL' ((Format-Procs $apps) + ' (close it, or pass -Force)')
      return $false
    }
    Stop-AnyApp 'preflight'
  }
  Add-Check 'preflight: no Rule Zero running' 'PASS' (Format-Procs (Get-AppProcesses))
  if (@(Get-InstallerProcesses).Count -gt 0) { Add-Check 'preflight: no installer running' 'FAIL' (Format-Procs (Get-InstallerProcesses)); return $false }
  if (Test-Path -LiteralPath $ConfigJson) {
    $cj = Get-Content -LiteralPath $ConfigJson -Raw
    $off = $cj -match '"autoUpdate"\s*:\s*\{[^}]*"enabled"\s*:\s*false'
    [void](Test-That 'preflight: config.json does not switch auto-update off' (-not $off) ($cj -replace '\s+', ' '))
  }
  foreach ($e in @(Get-ChildItem Env: | Where-Object { $_.Name -like 'RZ_*' })) { Add-Check "preflight: $($e.Name) in this shell is not passed to the app" 'INFO' $e.Value }
  return $true
}

# ---------------------------------------------------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------------------------------------------------
function Get-LogTailLines([int]$N) {
  if (-not (Test-Path -LiteralPath $DesktopLog)) { return @() }
  $fs = [IO.File]::Open($DesktopLog, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
  try {
    $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
    $all = $sr.ReadToEnd() -split "`r?`n" | ForEach-Object { $_.Replace([string][char]0, '').Trim() } | Where-Object { $_ }
  } finally { $fs.Dispose() }
  return @($all | Select-Object -Last $N)
}

function Write-Report {
  $fails = @($script:Checks | Where-Object { $_.status -eq 'FAIL' }).Count
  $passes = @($script:Checks | Where-Object { $_.status -eq 'PASS' }).Count
  $ok = ($fails -eq 0 -and $passes -gt 0)
  $u = Get-UninstallInfo
  $script:Final.installedVersion = $(if ($u) { [string]$u.DisplayVersion } else { $null })
  $tailLines = Get-LogTailLines 120
  $report = [ordered]@{
    result        = $(if ($ok) { 'PASS' } else { 'FAIL' })
    parameterSet  = $SetName
    repo          = $Repo
    fromVersion   = $FromVersion
    toVersion     = $ToVersion
    mode          = $(if ($SetName -eq 'Update') { $Mode } else { $null })
    tamperRepo    = $(if ($SetName -eq 'Tamper') { $TamperRepo } else { $null })
    tamperVersion = $TamperVersion
    machine       = [ordered]@{ computer = $env:COMPUTERNAME; user = $env:USERNAME; os = [Environment]::OSVersion.VersionString; ps = $PSVersionTable.PSVersion.ToString(); ci = [bool]$env:GITHUB_ACTIONS }
    started       = $script:T0.ToString('o')
    seconds       = [Math]::Round(((Get-Date) - $script:T0).TotalSeconds, 1)
    replaced      = $script:Pre
    final         = $script:Final
    counts        = [ordered]@{ pass = $passes; fail = $fails; skip = @($script:Checks | Where-Object { $_.status -eq 'SKIP' }).Count; info = @($script:Checks | Where-Object { $_.status -eq 'INFO' }).Count }
    runs          = $script:Runs
    checks        = $script:Checks
    patterns      = $P
    desktopLogTail = $tailLines
  }
  $json = Join-Path $WorkDir 'report.json'
  ConvertTo-Json -InputObject $report -Depth 8 | Set-Content -LiteralPath $json -Encoding UTF8

  $md = New-Object System.Collections.ArrayList
  $esc = { param($s) ([string]$s -replace '\|', '\|' -replace "`r?`n", ' ') }
  [void]$md.Add("# Rule Zero desktop E2E: $($report.result)")
  [void]$md.Add('')
  [void]$md.Add(('- set **{0}**, repo `{1}`, {2} -> {3}{4}' -f $report.parameterSet, $Repo, $FromVersion, $(if ($ToVersion) { $ToVersion } else { $TamperVersion }), $(if ($report.mode) { ", mode $($report.mode)" } elseif ($report.tamperRepo) { ", tamper repo ``$TamperRepo``" } else { '' })))
  [void]$md.Add(('- {0} pass, {1} fail, {2} skip, {3} info; {4:N0} s; {5}, {6}, PowerShell {7}' -f $passes, $fails, $report.counts.skip, $report.counts.info, $report.seconds, $env:COMPUTERNAME, $report.machine.os, $report.machine.ps))
  [void]$md.Add(('- install found before the run: **{0}**; after the run: **{1}**' -f $(if ($script:Pre.Contains('installedVersion') -and $script:Pre.installedVersion) { $script:Pre.installedVersion } else { 'none' }), $(if ($script:Final.installedVersion) { $script:Final.installedVersion } else { 'none' })))
  [void]$md.Add('')
  if ($script:Runs.Count -gt 0) {
    [void]$md.Add('| run | from -> to | delta | downloaded bytes | of bytes | % | app bytes | download s | install s |')
    [void]$md.Add('|---|---|---|---|---|---|---|---|---|')
    foreach ($r in $script:Runs) {
      $d = $r.download
      if ($d) {
        [void]$md.Add(('| {0} | {1} -> {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} |' -f $r.mode, $r.from, $r.to, $d.delta, $d.downloadBytes, $d.newFileBytes, $d.percent, $d.appBytes, $r.downloadSeconds, $(if ($r.Contains('installSeconds')) { $r.installSeconds } else { '' })))
      } else {
        [void]$md.Add(('| {0} | {1} -> {2} | not run | | | | | | |' -f $r.mode, $r.from, $r.to))
      }
    }
    [void]$md.Add('')
  }
  [void]$md.Add('| # | check | status | s | detail |')
  [void]$md.Add('|---|---|---|---|---|')
  $i = 0
  foreach ($c in $script:Checks) {
    $i++
    $st = $c.status
    if ($st -eq 'FAIL') { $st = '**FAIL**' }
    [void]$md.Add(('| {0} | {1} | {2} | {3} | {4} |' -f $i, (& $esc $c.name), $st, $c.seconds, (& $esc $c.detail)))
  }
  [void]$md.Add('')
  [void]$md.Add('## desktop.log (last 120 lines)')
  [void]$md.Add('')
  [void]$md.Add('```')
  foreach ($l in $tailLines) { [void]$md.Add($l) }
  [void]$md.Add('```')
  Set-Content -LiteralPath (Join-Path $WorkDir 'report.md') -Value @($md) -Encoding UTF8
  Write-Note ("report: {0} ({1} pass, {2} fail) in {3}" -f $report.result, $passes, $fails, $WorkDir)
  return $ok
}

# ---------------------------------------------------------------------------------------------------------------------
# Self-test (read-only)
# ---------------------------------------------------------------------------------------------------------------------
function Invoke-SelfTest {
  Write-Host '--- machine state (read-only) ---'
  $s = Get-InstallState
  foreach ($k in $s.Keys) {
    $v = $s[$k]
    if ($v -is [System.Collections.IDictionary]) {
      Write-Host ("{0}:" -f $k)
      foreach ($k2 in $v.Keys) { Write-Host ("    {0,-22} {1}" -f $k2, $v[$k2]) }
    } elseif ($v -is [array]) {
      Write-Host ("{0}: {1}" -f $k, $(if ($v.Count) { '' } else { 'none' }))
      foreach ($x in $v) { Write-Host "    $x" }
    } else {
      Write-Host ("{0,-26} {1}" -f $k, $v)
    }
  }
  Write-Host ('paths: install {0}; userData {1}; cache {2}; start menu {3}; desktop {4}' -f $InstallDir, $UserData, $UpdaterCache, $StartMenuLnk, $DesktopLnk)

  Write-Host '--- the install checks against what is installed now (informational: builds before the self-update differ) ---'
  $dv = Get-DisplayVersion
  if ($dv) {
    Test-InstallState $dv "installed $dv"
    $inst = Join-Path $UpdaterCache 'installer.exe'
    if (Test-Path -LiteralPath $inst) { Add-Check 'updater cache installer.exe sha256' 'INFO' (Get-Sha256 $inst) }
  } else {
    Add-Check 'installed version' 'INFO' 'none'
  }
  $installChecks = $script:Checks.Count
  $q = Get-RegValue $UninstallKey 'QuietUninstallString'
  if ($q) {
    $qs = Split-CommandLine ([string]$q)
    [void](Test-That 'parse QuietUninstallString' ($qs -and $qs.exe -like '*Uninstall Rule Zero.exe' -and $qs.args -eq '/currentuser /S') ("exe '{0}' args '{1}'" -f $qs.exe, $qs.args))
  }
  $lt = Get-LogTailLines 8
  Add-Check 'desktop.log last lines' 'INFO' ($lt -join ' || ')
  $tail = New-LogTail $DesktopLog
  [void](Test-That 'log tail starts at the current end' ((Update-LogTail $tail).Count -eq 0) ("offset $($tail.Offset)"))

  Write-Host '--- parsers against sample lines ---'
  $ts = '2026-11-26T01:00:00.000Z '
  $deltaLines = @(
    ($ts + 'update: available 0.2.3'),
    ($ts + 'Found version 0.2.3 (url: RuleZero-Setup-0.2.3.exe)'),
    ($ts + 'Download block maps (old: "https://github.com/raiyuza/rule-zero-desktop-test/releases/download/v0.2.2/RuleZero-Setup-0.2.2.exe.blockmap", new: https://github.com/raiyuza/rule-zero-desktop-test/releases/download/v0.2.3/RuleZero-Setup-0.2.3.exe.blockmap)'),
    ($ts + 'File has 57 changed blocks'),
    ($ts + 'Full: 227,148.21 KB, To download: 3,312.5 KB (1%)'),
    ($ts + 'update: signature ok RuleZero-Setup-0.2.3.exe key 715feb7a2810e479'),
    ($ts + 'New version 0.2.3 has been downloaded to C:\Users\x\AppData\Local\rule-zero-desktop-updater\pending\RuleZero-Setup-0.2.3.exe'),
    ($ts + 'update: downloaded 0.2.3 (3,392,000 bytes, delta)'),
    ($ts + 'Auto install update on quit'),
    ($ts + 'update: installing 0.2.3 on quit')
  )
  $d = Get-DeltaInfo $deltaLines
  [void](Test-That 'parse delta lines' ($d.delta -eq $true -and $d.downloadBytes -eq 3392000 -and $d.newFileBytes -eq 232599767 -and $d.appBytes -eq 3392000) ("delta {0}, {1} of {2} bytes ({3}%), app {4}" -f $d.delta, $d.downloadBytes, $d.newFileBytes, $d.percent, $d.appBytes))
  foreach ($pair in @(@('Available', '0.2.3'), @('Downloaded', '0.2.3'), @('SignatureOk', ''), @('Installing', ''))) {
    $hit = Find-Line $deltaLines (Expand-Pattern $pair[0] $pair[1])
    [void](Test-That ("pattern {0} matches the sample" -f $pair[0]) ($null -ne $hit) ([string]$hit))
  }
  [void](Test-That 'pattern Downloaded does not match another version' ($null -eq (Find-Line $deltaLines (Expand-Pattern 'Downloaded' '0.2.30'))))
  [void](Test-That 'pattern Started matches main.ts line' ('2026-11-19T18:27:17.089Z Rule Zero desktop 0.2.1 loading https://rule-zero.net/' -match (Expand-Pattern 'Started' '0.2.1')))
  $fb = Get-DeltaInfo @(($ts + 'Download block maps (old: "a", new: b)'), ($ts + 'Cannot download differentially, fallback to full download: Error: 404'), ($ts + 'update: downloaded 0.2.3 (232,599,767 bytes, full)'))
  [void](Test-That 'parse fallback lines' ($fb.delta -eq $false -and $fb.fallback -and $fb.appBytes -eq 232599767) ("delta {0}, app bytes {1}, source {2}" -f $fb.delta, $fb.appBytes, $fb.source))
  $ref = @(($ts + 'update: signature refused 0.2.99: signature does not verify'), ($ts + 'Error: Error: New version 0.2.99 is not signed by the application owner: sha512 mismatch'))
  [void](Test-That 'pattern SignatureRefused matches both forms' ((@($ref | Where-Object { $_ -match (Expand-Pattern 'SignatureRefused') })).Count -eq 2))
  [void](Test-That 'pattern SignatureOk does not match a refusal' ($null -eq (Find-Line $ref (Expand-Pattern 'SignatureOk'))))
  [void](Test-That 'pattern UpdateError ignores a normal run' ($null -eq (Find-Line $deltaLines (Expand-Pattern 'UpdateError'))))
  $sums = Read-Sha256Sums ("{0}  RuleZero-Setup-0.2.3.exe`n{1} *RuleZero-Setup-0.2.3.exe.blockmap`r`n" -f ('a' * 64), ('B' * 64))
  [void](Test-That 'parse SHA256SUMS.txt' ($sums['RuleZero-Setup-0.2.3.exe'] -eq ('a' * 64) -and $sums['RuleZero-Setup-0.2.3.exe.blockmap'] -eq ('b' * 64)) ("{0} entries" -f $sums.Count))
  [void](Test-That 'parse latest.yml' ((Get-YmlVersion "version: 0.2.3`nfiles:`n  - url: RuleZero-Setup-0.2.3.exe`n") -eq '0.2.3'))
  # A rotated log (file shorter than the offset) restarts at 0; a half-written last line waits.
  $tmp = Join-Path $env:TEMP ('rz-e2e-selftest-' + [guid]::NewGuid().ToString('N') + '.log')
  try {
    [IO.File]::WriteAllText($tmp, "one`ntwo`nthr")
    $t = New-LogTail $tmp
    $t.Offset = 0
    $a = Update-LogTail $t
    [IO.File]::AppendAllText($tmp, "ee`n")
    $b = Update-LogTail $t
    [IO.File]::WriteAllText($tmp, "new`n")
    $c = Update-LogTail $t
    [void](Test-That 'log tail: partial line, rotation' (($a -join ',') -eq 'one,two' -and ($b -join ',') -eq 'three' -and ($c -join ',') -eq 'new') ("{0} | {1} | {2}" -f ($a -join ','), ($b -join ','), ($c -join ',')))
    [IO.File]::AppendAllText($tmp, ($ts + "Full: 1,000 KB, To download: 10 KB (1%)`n" + $ts + "update: signature refused bad sig`n"))
    $w = Wait-LogEvents $t @{ plan = $P.DeltaPlan; refused = (Expand-Pattern 'SignatureRefused') } @{} 5 0
    [void](Test-That 'Wait-LogEvents finds both lines' ($w.Found.Count -eq 2 -and -not $w.TimedOut) ("found: " + (@($w.Found.Keys) -join ',')))
    $w2 = Wait-LogEvents $t @{ never = 'no such line' } @{} 2 0
    [void](Test-That 'Wait-LogEvents times out' ($w2.TimedOut -and $w2.Found.Count -eq 0))
  } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }

  if ($Repo) {
    Write-Host "--- feed $Repo (read-only) ---"
    try {
      $yml = Get-RemoteText ('https://github.com/{0}/releases/latest/download/latest.yml' -f $Repo)
      Add-Check "feed: latest.yml of $Repo" 'INFO' ("version " + (Get-YmlVersion $yml))
    } catch {
      Add-Check "feed: latest.yml of $Repo" 'INFO' ("not readable (no release yet?): " + $_.Exception.Message)
    }
  }
  # The exit code covers the script's own machinery; the install checks above only show what an E2E run would see.
  $installFails = @($script:Checks | Select-Object -First $installChecks | Where-Object { $_.status -eq 'FAIL' }).Count
  $fails = @($script:Checks | Select-Object -Skip $installChecks | Where-Object { $_.status -eq 'FAIL' }).Count
  Write-Host ("--- self-test: {0} checks; script checks failed: {1}; install checks that would fail on this install: {2} ---" -f $script:Checks.Count, $fails, $installFails)
  return ($fails -eq 0)
}

# ---------------------------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------------------------
if ($SetName -eq 'SelfTest') {
  if (Invoke-SelfTest) { exit 0 } else { exit 1 }
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$script:LogFile = Join-Path $WorkDir 'e2e.log'
Write-Note ("Rule Zero desktop E2E, set {0}, WorkDir {1}" -f $SetName, $WorkDir)
$allOk = $false
try {
  $go = $false
  [void](Invoke-Step 'preflight' { $script:go = Invoke-Preflight })
  $go = [bool]$script:go
  if ($go) {
    if ($SetName -eq 'Update') {
      if ((ConvertTo-Ver $ToVersion) -le (ConvertTo-Ver $FromVersion)) { Add-Check 'versions' 'FAIL' "ToVersion $ToVersion is not newer than $FromVersion" }
      [void](Invoke-Step "download $FromVersion" { Get-Installer $Repo $FromVersion })
      [void](Invoke-Step 'feed' {
        Test-Feed $Repo $ToVersion 'feed'
        # Only the sums of the target: the cache check after the update compares installer.exe with it.
        $sums = Read-Sha256Sums (Get-RemoteText (Get-ReleaseUrl $Repo $ToVersion 'SHA256SUMS.txt'))
        $f = $InstallerName -f $ToVersion
        if ($sums.ContainsKey($f)) { $script:Sha[$ToVersion] = $sums[$f] }
        [void](Test-That "feed: SHA256SUMS.txt of v$ToVersion names $f" ($sums.ContainsKey($f)) ([string]$script:Sha[$ToVersion]))
      })
      [void](Invoke-Step "install $FromVersion" { [void](Install-RZ $FromVersion "install $FromVersion") })
      if ($Mode -eq 'OnQuit' -or $Mode -eq 'Both') {
        [void](Invoke-Step 'update OnQuit' { Invoke-UpdateRun 'OnQuit' })
      }
      if ($Mode -eq 'WhenReady' -or $Mode -eq 'Both') {
        [void](Invoke-Step 'update WhenReady' {
          if ((Get-DisplayVersion) -ne $FromVersion -and $script:Touched -and $script:Installer.ContainsKey($FromVersion)) {
            # Back to FromVersion through a clean uninstall (installing an older build over a newer one is not what users do).
            Uninstall-RZ "reinstall $FromVersion"
            [void](Install-RZ $FromVersion "reinstall $FromVersion")
          }
          Invoke-UpdateRun 'WhenReady'
        })
      }
    } else {
      if ((ConvertTo-Ver $TamperVersion) -le (ConvertTo-Ver $FromVersion)) { Add-Check 'versions' 'FAIL' "TamperVersion $TamperVersion is not newer than $FromVersion" }
      [void](Invoke-Step "download $FromVersion" { Get-Installer $Repo $FromVersion })
      [void](Invoke-Step 'tamper feed' { Test-Feed $TamperRepo $TamperVersion 'tamper feed' })
      [void](Invoke-Step "install $FromVersion" { [void](Install-RZ $FromVersion "install $FromVersion") })
      [void](Invoke-Step 'tamper' { Invoke-TamperRun })
    }
    if ($KeepInstalled) {
      Add-Check 'uninstall' 'SKIP' '-KeepInstalled'
    } elseif (-not $script:Touched) {
      Add-Check 'uninstall' 'SKIP' 'this run installed nothing, so the existing install is left alone'
    } else {
      [void](Invoke-Step 'uninstall' { Uninstall-RZ 'uninstall'; Test-Uninstalled 'uninstall' })
    }
  }
} catch {
  Add-Check 'script' 'FAIL' ("unhandled: " + $_.Exception.Message)
} finally {
  try { $allOk = Write-Report } catch { Write-Note ("report failed: " + $_.Exception.Message); $allOk = $false }
}
if ($allOk) { exit 0 } else { exit 1 }
