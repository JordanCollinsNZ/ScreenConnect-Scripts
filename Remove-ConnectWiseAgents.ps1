#Requires -Version 5.1
<#
.SYNOPSIS
    Force-removes the ConnectWise Automate (LabTech) agent and ScreenConnect / ConnectWise Control
    access clients from Windows 10/11.

.DESCRIPTION
    Does NOT use WMI/CIM (no Win32_Product, no wmic.exe). Everything is done with the registry,
    msiexec.exe, sc.exe, schtasks.exe and the filesystem.

    For each product:
      1. Disable + stop services and kill processes (so nothing restarts or re-deploys mid-cleanup)
      2. Run a silent, logged MSI uninstall for every matching product code
      3. Delete services, folders, registry keys, Installer registration, scheduled tasks, firewall
         rules, Run entries, SafeBoot entries, event log sources and credential providers
      4. Anything still locked is scheduled for deletion at the next reboot

    The ConnectWise Automate Control Center (LTClient.exe / "LabTech Client" folder) is NOT touched.

    Exit codes: 0 = clean, 3010 = clean but reboot needed to finish, 1 = error / items left over.

.PARAMETER SkipAutomate
    Don't touch the Automate agent.

.PARAMETER SkipScreenConnect
    Don't touch ScreenConnect.

.PARAMETER ScreenConnectThumbprint
    Only remove ScreenConnect instances named "... Client (<thumbprint>)". Comma-separate several.
    Default: remove ALL ScreenConnect / ConnectWise Control client instances, including any that
    belong to other vendors.

.PARAMETER DryRun
    Only log what would be done.

.PARAMETER Detach
    Re-launch as SYSTEM through a one-off scheduled task, then exit. Use this when you push the
    script FROM Automate or ScreenConnect: the cleanup kills the agent that is running the script.

.PARAMETER LogPath
    Transcript location. Default: C:\Windows\Temp\CW-Agent-Removal_<timestamp>.log

.EXAMPLE
    .\Remove-ConnectWiseAgents.ps1 -DryRun

.EXAMPLE
    .\Remove-ConnectWiseAgents.ps1

.EXAMPLE
    .\Remove-ConnectWiseAgents.ps1 -Detach
    (when run from Automate's script engine or the ScreenConnect backstage/command toolbox)

.EXAMPLE
    .\Remove-ConnectWiseAgents.ps1 -SkipAutomate -ScreenConnectThumbprint a1b2c3d4e5f60718
#>
[CmdletBinding()]
param(
    [switch]$SkipAutomate,
    [switch]$SkipScreenConnect,
    [string[]]$ScreenConnectThumbprint,
    [switch]$DryRun,
    [switch]$Detach,
    [string]$LogPath
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$script:BoundParams    = $PSBoundParameters
$script:RebootRequired = $false
$TaskName = 'CW-Agent-Removal'
$StageDir = Join-Path $env:windir 'Temp'
if (-not $LogPath) {
    $LogPath = Join-Path $StageDir ('CW-Agent-Removal_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

# Thumbprint filter (accepts "a,b", "(a)", etc.)
$script:ScThumbs = @(
    $ScreenConnectThumbprint -split ',' |
        ForEach-Object { $_.Trim().Trim('(', ')', ' ') } |
        Where-Object { $_ }
)

#region ---------- Bootstrap: 64-bit, admin, detach ----------

function Get-ForwardedArgs {
    param([string[]]$Exclude = @())
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($key in $script:BoundParams.Keys) {
        if ($Exclude -contains $key) { continue }
        $val = $script:BoundParams[$key]
        if ($val -is [System.Management.Automation.SwitchParameter]) {
            if ($val.IsPresent) { $list.Add("-$key") }
        } else {
            $list.Add("-$key")
            $list.Add((@($val) -join ','))
        }
    }
    if (-not $script:BoundParams.ContainsKey('LogPath')) { $list.Add('-LogPath'); $list.Add($LogPath) }
    return ,$list.ToArray()
}

# Automate runs scripts in 32-bit PowerShell -> registry redirection would hide 64-bit keys.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:windir 'sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if ($PSCommandPath -and (Test-Path -LiteralPath $ps64)) {
        Write-Host 'Relaunching in 64-bit PowerShell...'
        $fwd = Get-ForwardedArgs
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @fwd
        exit $LASTEXITCODE
    }
    Write-Warning 'Running as 32-bit PowerShell on 64-bit Windows and cannot relaunch. Results may be incomplete.'
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'This script must be run elevated (Administrator or SYSTEM).'
    exit 1
}

if ($Detach) {
    if (-not $PSCommandPath) { Write-Error '-Detach only works when the script is run from a .ps1 file.'; exit 1 }
    $stagedPs1 = Join-Path $StageDir 'Remove-ConnectWiseAgents.ps1'
    $stagedCmd = Join-Path $StageDir 'Remove-ConnectWiseAgents.cmd'
    if ($PSCommandPath -ne $stagedPs1) { Copy-Item -LiteralPath $PSCommandPath -Destination $stagedPs1 -Force }

    $fwdRaw = Get-ForwardedArgs -Exclude 'Detach'   # assign first so the array is unrolled
    $fwd = $fwdRaw | ForEach-Object { if ($_ -match '^-\w+$') { $_ } else { '"' + $_ + '"' } }
    $ps  = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $line = '"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}" {2}' -f $ps, $stagedPs1, ($fwd -join ' ')
    Set-Content -LiteralPath $stagedCmd -Value "@echo off`r`n$line`r`n" -Encoding ASCII

    & schtasks.exe /Create /TN $TaskName /TR $stagedCmd /SC ONCE /ST 23:59 /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null
    & schtasks.exe /Run /TN $TaskName 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Cleanup launched in the background as SYSTEM (scheduled task '$TaskName')."
        Write-Host "Log: $LogPath"
        exit 0
    }
    Write-Error "Could not create/run scheduled task '$TaskName'."
    exit 1
}

try { Start-Transcript -Path $LogPath -Append -Force | Out-Null } catch { Write-Warning "Transcript failed: $_" }

if (-not ('CWCleanup.Native' -as [type])) {
    try {
        Add-Type -Namespace CWCleanup -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
    } catch { Write-Warning "Delete-on-reboot unavailable: $_" }
}

#endregion

#region ---------- Helpers ----------

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'OK', 'DRY')][string]$Level = 'INFO')
    $color = @{ INFO = 'Gray'; WARN = 'Yellow'; ERROR = 'Red'; OK = 'Green'; DRY = 'Cyan' }[$Level]
    Write-Host ('[{0}] [{1,-5}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message) -ForegroundColor $color
}

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor White
    Write-Host " $Title" -ForegroundColor White
    Write-Host ('=' * 70) -ForegroundColor White
}

function Test-ScMatch([string]$Text) {
    if (-not $Text) { return $false }
    if ($Text -notmatch 'ScreenConnect|ConnectWise Control') { return $false }
    if ($script:ScThumbs.Count -eq 0) { return $true }
    foreach ($t in $script:ScThumbs) {
        if ($Text -match ('\(' + [regex]::Escape($t) + '\)')) { return $true }
    }
    return $false
}

function ConvertFrom-PackedGuid([string]$Value) {
    # Works in both directions: packed <-> {GUID}. Returns {GUID} form.
    $s = $Value -replace '[{}-]', ''
    if ($s.Length -ne 32 -or $s -notmatch '^[0-9A-Fa-f]{32}$') { return $null }
    $rev  = { param($x) -join ($x.ToCharArray()[($x.Length - 1)..0]) }
    $swap = { param($x) -join (0..($x.Length / 2 - 1) | ForEach-Object { $x[2 * $_ + 1]; $x[2 * $_] }) }
    $p1 = & $rev  $s.Substring(0, 8)
    $p2 = & $rev  $s.Substring(8, 4)
    $p3 = & $rev  $s.Substring(12, 4)
    $p4 = & $swap $s.Substring(16, 4)
    $p5 = & $swap $s.Substring(20, 12)
    return ('{{{0}-{1}-{2}-{3}-{4}}}' -f $p1, $p2, $p3, $p4, $p5).ToUpper()
}

function ConvertTo-PackedGuid([string]$Guid) {
    $g = ConvertFrom-PackedGuid $Guid
    if ($g) { return ($g -replace '[{}-]', '') }
    return $null
}

function Get-LoadedUserHives {
    Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
        ForEach-Object { $_.PSChildName }
}

function Get-ProfilePaths {
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-' } |
        ForEach-Object { [Environment]::ExpandEnvironmentVariables([string]$_.GetValue('ProfileImagePath')) } |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) }
}

function Register-DeleteOnReboot([string]$Path) {
    if (-not ('CWCleanup.Native' -as [type])) { return }
    try {
        if (Test-Path -LiteralPath $Path -PathType Container) {
            Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
                ForEach-Object { [void][CWCleanup.Native]::MoveFileEx($_.FullName, $null, 4) }
            Get-ChildItem -LiteralPath $Path -Recurse -Force -Directory -ErrorAction SilentlyContinue |
                Sort-Object { $_.FullName.Length } -Descending |
                ForEach-Object { [void][CWCleanup.Native]::MoveFileEx($_.FullName, $null, 4) }
        }
        [void][CWCleanup.Native]::MoveFileEx($Path, $null, 4)   # MOVEFILE_DELAY_UNTIL_REBOOT
        $script:RebootRequired = $true
        Write-Log "Scheduled for deletion at next reboot: $Path" WARN
    } catch {
        Write-Log "Could not schedule delete-on-reboot for ${Path}: $_" ERROR
    }
}

function Remove-PathSafe([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
    if ($DryRun) { Write-Log "Would delete: $Path" DRY; return }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Log "Deleted: $Path" OK
        return
    } catch { }

    # Take ownership + grant Administrators full control, then retry
    & takeown.exe /F "$Path" /A /R /D Y 2>&1 | Out-Null
    & icacls.exe "$Path" /grant '*S-1-5-32-544:F' /T /C /Q 2>&1 | Out-Null
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Log "Deleted (after taking ownership): $Path" OK
        return
    } catch {
        Write-Log "Could not fully delete (files in use?): $Path" WARN
    }
    if (Test-Path -LiteralPath $Path) { Register-DeleteOnReboot $Path }
}

function Remove-PathPatterns {
    param([string[]]$Patterns, [scriptblock]$NameFilter)
    foreach ($pat in $Patterns) {
        if (-not $pat -or $pat -match '^\\') { continue }   # env var was empty
        foreach ($item in @(Get-Item -Path $pat -Force -ErrorAction SilentlyContinue)) {
            if ($NameFilter -and -not (& $NameFilter $item.Name)) { continue }
            Remove-PathSafe $item.FullName
        }
    }
}

function Remove-RegKeySafe([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
    $display = $Path -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
    if ($DryRun) { Write-Log "Would delete registry key: $display" DRY; return }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Log "Deleted registry key: $display" OK
    } catch {
        Write-Log "Failed to delete registry key ${display}: $($_.Exception.Message)" ERROR
    }
}

function Remove-RegChildren {
    param([string]$Parent, [scriptblock]$NameFilter)
    foreach ($k in @(Get-ChildItem -LiteralPath $Parent -ErrorAction SilentlyContinue)) {
        if (& $NameFilter $k.PSChildName) { Remove-RegKeySafe $k.PSPath }
    }
}

function Remove-RegValuesMatching {
    param([string]$KeyPath, [scriptblock]$Predicate)
    $k = Get-Item -LiteralPath $KeyPath -ErrorAction SilentlyContinue
    if (-not $k) { return }
    foreach ($vn in $k.GetValueNames()) {
        $data = [string]$k.GetValue($vn)
        if (& $Predicate $vn $data) {
            if ($DryRun) { Write-Log "Would delete registry value: $KeyPath\$vn" DRY; continue }
            try {
                Remove-ItemProperty -LiteralPath $KeyPath -Name $vn -Force -ErrorAction Stop
                Write-Log "Deleted registry value: $KeyPath\$vn" OK
            } catch { Write-Log "Failed to delete value $KeyPath\${vn}: $($_.Exception.Message)" ERROR }
        }
    }
}

function Get-ExeFromImagePath([string]$ImagePath) {
    if ($ImagePath -match '^\s*"([^"]+)"') { return $Matches[1] }
    if ($ImagePath -match '^\s*(.+?\.exe)\b') { return $Matches[1] }
    return $null
}

function Stop-ProcessSafe($Process) {
    if ($Process.Id -eq $PID) { return }
    if ($DryRun) { Write-Log "Would kill process $($Process.ProcessName) (PID $($Process.Id))" DRY; return }
    try {
        Stop-Process -Id $Process.Id -Force -ErrorAction Stop
        Write-Log "Killed process $($Process.ProcessName) (PID $($Process.Id))" OK
    } catch {
        Write-Log "Could not kill $($Process.ProcessName) (PID $($Process.Id)): $($_.Exception.Message)" WARN
    }
}

function Stop-MatchingProcesses {
    param([string]$NameRegex, [scriptblock]$PathPredicate)
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $path = $null
        try { $path = $p.Path } catch { }
        $hit = ($NameRegex -and $p.ProcessName -match $NameRegex) -or
               ($PathPredicate -and $path -and (& $PathPredicate $path))
        if ($hit) { Stop-ProcessSafe $p }
    }
}

function Get-ServiceNamesMatching([scriptblock]$Predicate) {
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($k in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue)) {
        $image = [string]$k.GetValue('ImagePath')
        if (& $Predicate $k.PSChildName $image) { $names.Add($k.PSChildName) }
    }
    return ,$names.ToArray()
}

function Stop-ServiceHard([string]$Name) {
    $key = Get-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -ErrorAction SilentlyContinue
    $image = if ($key) { [string]$key.GetValue('ImagePath') } else { $null }
    if ($DryRun) { Write-Log "Would disable + stop service '$Name'" DRY; return }

    Write-Log "Disabling and stopping service '$Name'"
    # A disabled service can't be restarted by its recovery actions or by a watchdog (LTSvcMon)
    & sc.exe config "$Name" start= disabled 2>&1 | Out-Null
    & sc.exe stop "$Name" 2>&1 | Out-Null

    $deadline = (Get-Date).AddSeconds(20)
    do {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.Status -eq 'Stopped') { break }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    $exe = Get-ExeFromImagePath $image
    if ($exe) {
        foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
            $path = $null
            try { $path = $p.Path } catch { }
            if ($path -and $path -eq $exe) { Stop-ProcessSafe $p }
        }
    }
}

function Remove-ServiceHard([string]$Name) {
    if ($DryRun) { Write-Log "Would delete service '$Name'" DRY; return }
    & sc.exe delete "$Name" 2>&1 | Out-Null
    switch ($LASTEXITCODE) {
        0       { Write-Log "Deleted service '$Name'" OK }
        1060    { }   # does not exist
        1072    { Write-Log "Service '$Name' is marked for deletion (finishes at reboot)" WARN; $script:RebootRequired = $true }
        default { Write-Log "sc.exe delete '$Name' returned $LASTEXITCODE" WARN }
    }
    Remove-RegKeySafe "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
}

function Get-UninstallEntries {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $roots += Get-LoadedUserHives | ForEach-Object { "Registry::HKEY_USERS\$_\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    foreach ($r in $roots) {
        foreach ($k in @(Get-ChildItem -LiteralPath $r -ErrorAction SilentlyContinue)) {
            [pscustomobject]@{
                Key             = $k.PSPath
                KeyName         = $k.PSChildName
                DisplayName     = [string]$k.GetValue('DisplayName')
                UninstallString = [string]$k.GetValue('UninstallString')
            }
        }
    }
}

function Get-InstallerProducts {
    foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products' -ErrorAction SilentlyContinue)) {
        [pscustomobject]@{
            Packed      = $k.PSChildName
            ProductCode = ConvertFrom-PackedGuid $k.PSChildName
            ProductName = [string]$k.GetValue('ProductName')
        }
    }
}

function Get-ProductCodes {
    param([scriptblock]$Predicate, [string[]]$KnownCodes = @())
    $found = @{}
    foreach ($e in Get-UninstallEntries) {
        if ($e.DisplayName -and (& $Predicate $e.DisplayName)) {
            $code = $null
            if ($e.KeyName -match '^\{[0-9A-Fa-f-]{36}\}$') { $code = $e.KeyName.ToUpper() }
            elseif ($e.UninstallString -match '(?i)msiexec.*?(\{[0-9A-F-]{36}\})') { $code = $Matches[1].ToUpper() }
            if ($code) { $found[$code] = $e.DisplayName }
        }
    }
    foreach ($p in Get-InstallerProducts) {
        if ($p.ProductCode -and $p.ProductName -and (& $Predicate $p.ProductName)) { $found[$p.ProductCode] = $p.ProductName }
    }
    foreach ($c in $KnownCodes) {
        $c = $c.ToUpper()
        if ($found.ContainsKey($c)) { continue }
        $packed = ConvertTo-PackedGuid $c
        if ((Test-Path "HKLM:\SOFTWARE\Classes\Installer\Products\$packed") -or
            (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$c") -or
            (Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$c")) {
            $found[$c] = '(known product code)'
        }
    }
    return $found
}

function Invoke-MsiUninstall([string]$ProductCode, [string]$Label) {
    if ($DryRun) { Write-Log "Would run: msiexec /x $ProductCode /qn  ($Label)" DRY; return }
    $msiLog = Join-Path $StageDir ('msi_uninstall_{0}.log' -f $ProductCode.Trim('{}'))
    Write-Log "MSI uninstall $ProductCode ($Label)  log: $msiLog"
    $p = Start-Process -FilePath "$env:windir\System32\msiexec.exe" -PassThru -WindowStyle Hidden `
        -ArgumentList "/x $ProductCode /qn /norestart REBOOT=ReallySuppress /L*v `"$msiLog`""
    $null = $p.Handle   # needed so ExitCode is populated on PS 5.1
    if (-not $p.WaitForExit(600000)) {
        Write-Log 'msiexec did not finish in 10 minutes - killing it and continuing with manual cleanup' WARN
        try { $p.Kill() } catch { }
        return
    }
    switch ($p.ExitCode) {
        0       { Write-Log 'MSI uninstall succeeded' OK }
        1605    { Write-Log 'MSI says product is not installed (cleaning leftovers manually)' INFO }
        1618    { Write-Log 'Another installation is in progress (1618) - manual cleanup will continue' WARN }
        { $_ -in 1641, 3010 } { Write-Log 'MSI uninstall succeeded (reboot required)' OK; $script:RebootRequired = $true }
        default { Write-Log "MSI uninstall failed with exit code $($p.ExitCode) - continuing with manual cleanup" WARN }
    }
}

function Remove-MsiLeftovers([string]$ProductCode) {
    $packed = ConvertTo-PackedGuid $ProductCode
    if (-not $packed) { return }
    Remove-RegKeySafe "HKLM:\SOFTWARE\Classes\Installer\Products\$packed"
    Remove-RegKeySafe "HKLM:\SOFTWARE\Classes\Installer\Features\$packed"
    Remove-RegKeySafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\$packed"
    Remove-RegKeySafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
    Remove-RegKeySafe "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
    foreach ($uc in @(Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes' -ErrorAction SilentlyContinue)) {
        if ($uc.GetValueNames() -contains $packed) {
            if ($uc.ValueCount -le 1) { Remove-RegKeySafe $uc.PSPath }
            elseif ($DryRun) { Write-Log "Would remove $packed from $($uc.PSChildName)" DRY }
            else { Remove-ItemProperty -LiteralPath $uc.PSPath -Name $packed -Force -ErrorAction SilentlyContinue }
        }
    }
}

function Remove-ArpEntries([scriptblock]$Predicate) {
    foreach ($e in Get-UninstallEntries) {
        if ($e.DisplayName -and (& $Predicate $e.DisplayName)) { Remove-RegKeySafe $e.Key }
    }
}

function Remove-MatchingScheduledTasks([scriptblock]$Predicate) {
    # Read task XML straight from disk - no COM/CIM needed, locale-independent
    $root = Join-Path $env:windir 'System32\Tasks'
    foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        $tn = $f.FullName.Substring($root.Length)
        if ($tn -eq "\$TaskName") { continue }
        $xml = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
        if ($xml -and (& $Predicate $xml)) {
            if ($DryRun) { Write-Log "Would delete scheduled task: $tn" DRY; continue }
            & schtasks.exe /Delete /TN "$tn" /F 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { Write-Log "Deleted scheduled task: $tn" OK }
            else { Write-Log "Failed to delete scheduled task: $tn" WARN }
        }
    }
}

function Remove-MatchingFirewallRules([scriptblock]$Predicate) {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
    $k = Get-Item -LiteralPath $key -ErrorAction SilentlyContinue
    if (-not $k) { return }
    foreach ($id in $k.GetValueNames()) {
        $data = [string]$k.GetValue($id)
        if (-not (& $Predicate $data)) { continue }
        $name = if ($data -match '\|Name=([^|]+)') { $Matches[1] } else { $id }
        if ($DryRun) { Write-Log "Would delete firewall rule: $name" DRY; continue }
        try {
            Remove-NetFirewallRule -Name $id -ErrorAction Stop
        } catch {
            Remove-ItemProperty -LiteralPath $key -Name $id -Force -ErrorAction SilentlyContinue
        }
        Write-Log "Deleted firewall rule: $name" OK
    }
}

function Get-RunKeys {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($sid in Get-LoadedUserHives) {
        $keys += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Run"
        $keys += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    return $keys
}

#endregion

#region ---------- Product definitions ----------

# --- ConnectWise Automate agent ---
$LtServiceNames    = @('LTService', 'LTSvcMon', 'LabVNC')
$LtSvcPredicate    = { param($name, $image) ($LtServiceNames -contains $name) -or ($image -match '\\LTSvc\\') }
$LtProductPredicate = { param($n) ($n -match 'LabTech|ConnectWise Automate') -and ($n -match 'Agent|Remote') -and ($n -notmatch 'Control Center') }
$LtPathPredicate   = { param($p) $p -match '\\LTSvc\\' }
$LtTextPredicate   = { param($t) $t -match '\\LTSvc\\|LTTray|LabTech Agent|LabTech\\Service' }
$LtProcessRegex    = '^(LTSVC|LTSvcMon|LTTray|LabVNC)$'
$LtKnownCodes      = @('{58A3001D-B675-4D67-A5A1-0FA9F08CF7CA}')   # LabTech/Automate agent MSI
$LtFolders = @(
    "$env:windir\LTSvc",
    "$env:windir\Temp\LabTech",
    "$env:windir\Temp\_LTUpdate",
    "$env:windir\SystemTemp\LabTech",
    "$env:windir\SystemTemp\_LTUpdate"
)
$LtRegKeys = @(
    'HKLM:\SOFTWARE\LabTech',
    'HKLM:\SOFTWARE\WOW6432Node\LabTech',
    'HKLM:\SOFTWARE\LabTechMSP',
    'HKLM:\SOFTWARE\WOW6432Node\LabTechMSP'
)

# --- ScreenConnect / ConnectWise Control client ---
$ScSvcPredicate     = { param($name, $image) (Test-ScMatch $name) -or (($image -match 'ScreenConnect\.') -and (Test-ScMatch $image)) }
$ScProductPredicate = { param($n) ($n -match '(ScreenConnect|ConnectWise Control) Client') -and (Test-ScMatch $n) }
$ScPathPredicate    = { param($p) Test-ScMatch $p }
$ScProcessRegex     = if ($script:ScThumbs.Count -eq 0) { '^ScreenConnect\.' } else { $null }
$ScFolders = @(
    "${env:ProgramFiles(x86)}\ScreenConnect Client (*)",
    "$env:ProgramFiles\ScreenConnect Client (*)",
    "${env:ProgramFiles(x86)}\ConnectWise Control Client (*)",
    "$env:ProgramFiles\ConnectWise Control Client (*)",
    "$env:ProgramData\ScreenConnect Client (*)",
    "$env:ProgramData\ConnectWise Control Client (*)"
)
$ScSharedFolders = @(   # only removed when no thumbprint filter is used
    "$env:windir\Temp\ScreenConnect",
    "$env:windir\SystemTemp\ScreenConnect"
)

#endregion

#region ---------- Removal routines ----------

function Invoke-AutomateRemoval {
    Write-Section 'ConnectWise Automate (LabTech) agent'

    $services = Get-ServiceNamesMatching $LtSvcPredicate
    Write-Log ("Services found: {0}" -f ($(if ($services) { $services -join ', ' } else { 'none' })))
    foreach ($s in $services) { Stop-ServiceHard $s }
    Stop-MatchingProcesses -NameRegex $LtProcessRegex -PathPredicate $LtPathPredicate

    $codes = Get-ProductCodes -Predicate $LtProductPredicate -KnownCodes $LtKnownCodes
    if ($codes.Count -eq 0) { Write-Log 'No Automate agent MSI registration found' }
    foreach ($code in @($codes.Keys)) { Invoke-MsiUninstall $code $codes[$code] }

    # msiexec custom actions may have restarted something
    Stop-MatchingProcesses -NameRegex $LtProcessRegex -PathPredicate $LtPathPredicate

    foreach ($s in (Get-ServiceNamesMatching $LtSvcPredicate)) { Remove-ServiceHard $s }
    foreach ($code in @($codes.Keys)) { Remove-MsiLeftovers $code }
    Remove-ArpEntries $LtProductPredicate

    Remove-PathPatterns -Patterns $LtFolders
    foreach ($k in $LtRegKeys) { Remove-RegKeySafe $k }

    $evtFilter = { param($n) ($LtServiceNames -contains $n) -or ($n -match '^LabTech') }
    Remove-RegChildren 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application' $evtFilter
    foreach ($mode in 'Minimal', 'Network') {
        Remove-RegChildren "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode" { param($n) $LtServiceNames -contains $n }
    }

    foreach ($rk in Get-RunKeys) { Remove-RegValuesMatching $rk { param($n, $d) & $LtTextPredicate $d } }
    Remove-MatchingScheduledTasks $LtTextPredicate
    Remove-MatchingFirewallRules { param($d) $d -match '\\LTSvc\\' }
}

function Invoke-ScreenConnectRemoval {
    Write-Section 'ScreenConnect / ConnectWise Control client'
    if ($script:ScThumbs.Count) { Write-Log ("Limited to instance(s): {0}" -f ($script:ScThumbs -join ', ')) }
    else { Write-Log 'Removing ALL ScreenConnect / ConnectWise Control client instances' }

    $services = Get-ServiceNamesMatching $ScSvcPredicate
    Write-Log ("Services found: {0}" -f ($(if ($services) { $services -join ', ' } else { 'none' })))
    foreach ($s in $services) { Stop-ServiceHard $s }
    Stop-MatchingProcesses -NameRegex $ScProcessRegex -PathPredicate $ScPathPredicate

    $codes = Get-ProductCodes -Predicate $ScProductPredicate
    if ($codes.Count -eq 0) { Write-Log 'No ScreenConnect MSI registration found' }
    foreach ($code in @($codes.Keys)) { Invoke-MsiUninstall $code $codes[$code] }

    Stop-MatchingProcesses -NameRegex $ScProcessRegex -PathPredicate $ScPathPredicate

    foreach ($s in (Get-ServiceNamesMatching $ScSvcPredicate)) { Remove-ServiceHard $s }
    foreach ($code in @($codes.Keys)) { Remove-MsiLeftovers $code }
    Remove-ArpEntries $ScProductPredicate

    # Credential providers / filters registered from a ScreenConnect DLL
    $cpBases = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters'
    )
    foreach ($base in $cpBases) {
        foreach ($cp in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
            $clsid = $cp.PSChildName
            $dll = $null
            foreach ($c in "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32", "HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID\$clsid\InprocServer32") {
                $i = Get-Item -LiteralPath $c -ErrorAction SilentlyContinue
                if ($i) { $dll = [string]$i.GetValue(''); break }
            }
            if ($dll -and (Test-ScMatch $dll)) {
                Write-Log "ScreenConnect credential provider $clsid -> $dll"
                Remove-RegKeySafe $cp.PSPath
                Remove-RegKeySafe "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
                Remove-RegKeySafe "HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID\$clsid"
                $script:RebootRequired = $true
            }
        }
    }

    # LSA packages (only if one references ScreenConnect; only when removing all instances)
    if ($script:ScThumbs.Count -eq 0) {
        $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        foreach ($vn in 'Authentication Packages', 'Security Packages', 'Notification Packages') {
            $vals = @((Get-ItemProperty -LiteralPath $lsa -Name $vn -ErrorAction SilentlyContinue).$vn)
            $keep = [string[]]@($vals | Where-Object { $_ -and $_ -notmatch 'ScreenConnect' })
            if ($vals.Count -gt 0 -and $keep.Count -lt @($vals | Where-Object { $_ }).Count) {
                if ($DryRun) { Write-Log "Would remove ScreenConnect entry from LSA '$vn'" DRY; continue }
                Set-ItemProperty -LiteralPath $lsa -Name $vn -Value $keep -Type MultiString
                Write-Log "Removed ScreenConnect entry from LSA '$vn'" OK
                $script:RebootRequired = $true
            }
        }
    }

    # Folders (machine-wide + per user profile)
    Remove-PathPatterns -Patterns $ScFolders -NameFilter { param($n) Test-ScMatch $n }
    $userPatterns = foreach ($prof in Get-ProfilePaths) {
        "$prof\AppData\Local\ScreenConnect Client (*)"
        "$prof\AppData\Roaming\ScreenConnect Client (*)"
        "$prof\AppData\Local\ConnectWise Control Client (*)"
        "$prof\AppData\Roaming\ConnectWise Control Client (*)"
    }
    Remove-PathPatterns -Patterns $userPatterns -NameFilter { param($n) Test-ScMatch $n }
    if ($script:ScThumbs.Count -eq 0) {
        Remove-PathPatterns -Patterns $ScSharedFolders
        Remove-PathPatterns -Patterns (Get-ProfilePaths | ForEach-Object { "$_\AppData\Local\Temp\ScreenConnect" })
    }

    # Registry
    foreach ($root in 'HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\WOW6432Node') {
        Remove-RegChildren $root { param($n) Test-ScMatch $n }
    }
    Remove-RegChildren 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application' { param($n) Test-ScMatch $n }
    foreach ($mode in 'Minimal', 'Network') {
        Remove-RegChildren "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode" { param($n) Test-ScMatch $n }
    }

    foreach ($rk in Get-RunKeys) { Remove-RegValuesMatching $rk { param($n, $d) Test-ScMatch $d } }
    Remove-MatchingScheduledTasks { param($x) Test-ScMatch $x }
    Remove-MatchingFirewallRules  { param($d) Test-ScMatch $d }
}

function Test-Remaining {
    Write-Section 'Verification'
    $left = New-Object System.Collections.Generic.List[string]

    if (-not $SkipAutomate) {
        foreach ($s in (Get-ServiceNamesMatching $LtSvcPredicate)) { $left.Add("Service: $s") }
        foreach ($f in $LtFolders) { if (Test-Path -LiteralPath $f) { $left.Add("Folder: $f") } }
        foreach ($e in Get-UninstallEntries) { if ($e.DisplayName -and (& $LtProductPredicate $e.DisplayName)) { $left.Add("Programs entry: $($e.DisplayName)") } }
    }
    if (-not $SkipScreenConnect) {
        foreach ($s in (Get-ServiceNamesMatching $ScSvcPredicate)) { $left.Add("Service: $s") }
        foreach ($pat in $ScFolders) {
            if (-not $pat -or $pat -match '^\\') { continue }
            foreach ($i in @(Get-Item -Path $pat -Force -ErrorAction SilentlyContinue)) { if (Test-ScMatch $i.Name) { $left.Add("Folder: $($i.FullName)") } }
        }
        foreach ($e in Get-UninstallEntries) { if ($e.DisplayName -and (& $ScProductPredicate $e.DisplayName)) { $left.Add("Programs entry: $($e.DisplayName)") } }
    }

    if ($left.Count -eq 0) { Write-Log 'Nothing left behind.' OK }
    else { foreach ($l in $left) { Write-Log "Still present: $l" WARN } }
    return $left.Count
}

#endregion

#region ---------- Main ----------

Write-Section 'ConnectWise Automate + ScreenConnect removal'
Write-Log "Computer: $env:COMPUTERNAME   User: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Log "Log: $LogPath"
if ($DryRun) { Write-Log 'DRY RUN - nothing will be changed' DRY }

# Automate first: it can re-deploy ScreenConnect if it is still running.
if (-not $SkipAutomate)      { Invoke-AutomateRemoval }
if (-not $SkipScreenConnect) { Invoke-ScreenConnectRemoval }

$remaining = if ($DryRun) { 0 } else { Test-Remaining }

# Clean up the -Detach scaffolding
if (-not $DryRun) {
    & schtasks.exe /Query /TN $TaskName 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { & schtasks.exe /Delete /TN $TaskName /F 2>&1 | Out-Null }
    Remove-Item -LiteralPath (Join-Path $StageDir 'Remove-ConnectWiseAgents.cmd') -Force -ErrorAction SilentlyContinue
}

Write-Section 'Done'
$exitCode = 0
if ($script:RebootRequired) {
    Write-Log 'A reboot is required to finish removing locked files/services.' WARN
    $exitCode = 3010
}
if ($remaining -gt 0) {
    Write-Log "$remaining item(s) still present - see above (a reboot + re-run usually clears them)." WARN
    if (-not $script:RebootRequired) { $exitCode = 1 }
}
if ($exitCode -eq 0) { Write-Log 'Removal complete.' OK }

try { Stop-Transcript | Out-Null } catch { }
exit $exitCode

#endregion
