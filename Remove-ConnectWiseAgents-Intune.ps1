#Requires -Version 5.1
<#
.SYNOPSIS
    Intune version: removes the ConnectWise Automate (LabTech) agent and ScreenConnect /
    ConnectWise Control clients.

.DESCRIPTION
    Deploy as an Intune Platform script (Devices > Scripts and remediations > Platform scripts >
    Add > Windows 10 and later) with:
        Run this script using the logged on credentials : No   (runs as SYSTEM)
        Enforce script signature check                   : No
        Run script in 64 bit PowerShell Host            : Yes
    and assign it to a DEVICE group.

    Intune can't pass parameters, so options are set in the CONFIGURATION block below.

    What it does (no WMI/CIM - registry, msiexec, sc.exe, schtasks.exe and the file system only):
      1. Disables + stops the services and kills the processes, so nothing restarts mid-cleanup
      2. Silent MSI uninstall of every matching product
      3. Removes services, folders, registry keys, Windows Installer registration, scheduled tasks,
         firewall rules, Run / Safe Mode entries, event log sources and credential providers
      4. Anything still locked is scheduled for deletion at the next reboot
      5. Reverts the Windows Update changes made by Automate patch management, so Intune /
         Windows Autopatch can manage updates
    The Automate part mirrors ConnectWise's own Agent_Uninstall.exe / LabUninstall.exe (v31.1).
    The Automate Control Center is never touched, and nothing Automate-related is removed on an
    Automate server.

    Exit codes (what Intune reports):
        0 = removed. Also 0 when the only thing left is a reboot to delete locked files - those are
            already scheduled for deletion and the log says so.
        1 = something could not be removed. Intune retries the script (up to 3 times).

    Log: C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\CW-Agent-Removal.log
         (picked up by "Collect diagnostics" on the device in Intune)

    Safe to run more than once.
#>

#region ---------- CONFIGURATION ----------

$RemoveAutomate           = $true
$RemoveScreenConnect      = $true

# Empty = remove ALL ScreenConnect / ConnectWise Control clients (including other vendors').
# To remove only yours, list its instance ID(s), e.g. @('a1b2c3d4e5f60718')
$ScreenConnectThumbprints = @()

# Revert Automate's Windows Update policies and re-enable the Update Orchestrator service.
# Leave $true for Intune / Autopatch to take over patching.
$ResetWindowsUpdate       = $true

#endregion

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$LogDir  = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs'
$LogPath = Join-Path $LogDir 'CW-Agent-Removal.log'
$MsiLogDir = Join-Path $env:windir 'Temp'

$script:RebootRequired = $false
$script:PendingDelete  = New-Object System.Collections.Generic.List[string]
$script:ScThumbs = @(
    $ScreenConnectThumbprints |
        ForEach-Object { ([string]$_).Trim().Trim('(', ')', ' ') } |
        Where-Object { $_ }
)

#region ---------- Bootstrap ----------

# In case "Run script in 64 bit PowerShell Host" was left at No
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:windir 'sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if ($PSCommandPath -and (Test-Path -LiteralPath $ps64)) {
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit $LASTEXITCODE
    }
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Not running as SYSTEM/admin. In Intune set 'Run this script using the logged on credentials' to No."
    exit 1
}

if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
if ((Test-Path -LiteralPath $LogPath) -and (Get-Item -LiteralPath $LogPath).Length -gt 5MB) {
    Move-Item -LiteralPath $LogPath -Destination "$LogPath.old" -Force
}

if (-not ('CWCleanup.Native' -as [type])) {
    try {
        Add-Type -Namespace CWCleanup -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
    } catch { }
}

#endregion

#region ---------- Helpers ----------

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO')
    $line = '{0} [{1,-5}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    try { Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
}

function Write-Section([string]$Title) {
    Write-Log ('---------- {0} ----------' -f $Title)
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
    # Packed <-> {GUID} conversion is its own inverse. Returns {GUID} form.
    $s = $Value -replace '[{}-]', ''
    if ($s -notmatch '^[0-9A-Fa-f]{32}$') { return $null }
    $rev  = { param($x) -join ($x.ToCharArray()[($x.Length - 1)..0]) }
    $swap = { param($x) -join (0..($x.Length / 2 - 1) | ForEach-Object { $x[2 * $_ + 1]; $x[2 * $_] }) }
    return ('{{{0}-{1}-{2}-{3}-{4}}}' -f (& $rev $s.Substring(0, 8)), (& $rev $s.Substring(8, 4)),
        (& $rev $s.Substring(12, 4)), (& $swap $s.Substring(16, 4)), (& $swap $s.Substring(20, 12))).ToUpper()
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
    if (-not ('CWCleanup.Native' -as [type])) {
        Write-Log "Can't schedule delete-on-reboot (Add-Type unavailable): $Path" ERROR
        return
    }
    try {
        if (Test-Path -LiteralPath $Path -PathType Container) {
            Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
                ForEach-Object { [void][CWCleanup.Native]::MoveFileEx($_.FullName, $null, 4) }
            Get-ChildItem -LiteralPath $Path -Recurse -Force -Directory -ErrorAction SilentlyContinue |
                Sort-Object { $_.FullName.Length } -Descending |
                ForEach-Object { [void][CWCleanup.Native]::MoveFileEx($_.FullName, $null, 4) }
        }
        if (-not [CWCleanup.Native]::MoveFileEx($Path, $null, 4)) {   # MOVEFILE_DELAY_UNTIL_REBOOT
            Write-Log "Could not schedule delete-on-reboot for $Path (error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))" ERROR
            return
        }
        $script:PendingDelete.Add($Path)
        $script:RebootRequired = $true
        Write-Log "Locked - will be deleted at next reboot: $Path" WARN
    } catch {
        Write-Log "Could not schedule delete-on-reboot for ${Path}: $_" ERROR
    }
}

function Test-PendingDelete([string]$Path) {
    foreach ($p in $script:PendingDelete) { if ($p.TrimEnd('\') -eq $Path.TrimEnd('\')) { return $true } }
    return $false
}

function Remove-PathSafe([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Log "Deleted: $Path" OK
        return
    } catch { }

    # Take ownership + give Administrators full control, then retry
    & takeown.exe /F "$Path" /A /R /D Y 2>&1 | Out-Null
    & icacls.exe "$Path" /grant '*S-1-5-32-544:F' /T /C /Q 2>&1 | Out-Null
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Log "Deleted (after taking ownership): $Path" OK
        return
    } catch { }
    if (Test-Path -LiteralPath $Path) { Register-DeleteOnReboot $Path }
}

function Remove-PathPatterns([string[]]$Patterns, [scriptblock]$NameFilter) {
    foreach ($pat in $Patterns) {
        if (-not $pat -or $pat -match '^\\') { continue }   # an environment variable was empty
        foreach ($item in @(Get-Item -Path $pat -Force -ErrorAction SilentlyContinue)) {
            if ($NameFilter -and -not (& $NameFilter $item.Name)) { continue }
            Remove-PathSafe $item.FullName
        }
    }
}

function Remove-RegKeySafe([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
    $display = $Path -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Log "Deleted registry key: $display" OK
    } catch {
        Write-Log "Failed to delete registry key ${display}: $($_.Exception.Message)" ERROR
    }
}

function Remove-RegChildren([string]$Parent, [scriptblock]$NameFilter) {
    foreach ($k in @(Get-ChildItem -LiteralPath $Parent -ErrorAction SilentlyContinue)) {
        if (& $NameFilter $k.PSChildName) { Remove-RegKeySafe $k.PSPath }
    }
}

function Remove-RegValuesMatching([string]$KeyPath, [scriptblock]$Predicate) {
    $k = Get-Item -LiteralPath $KeyPath -ErrorAction SilentlyContinue
    if (-not $k) { return }
    foreach ($vn in $k.GetValueNames()) {
        $data = [string]$k.GetValue($vn)
        if (-not (& $Predicate $vn $data)) { continue }
        try {
            Remove-ItemProperty -LiteralPath $KeyPath -Name $vn -Force -ErrorAction Stop
            Write-Log "Deleted registry value: $KeyPath\$vn (was: $data)" OK
        } catch { Write-Log "Failed to delete value $KeyPath\${vn}: $($_.Exception.Message)" ERROR }
    }
}

function Get-ExeFromImagePath([string]$ImagePath) {
    if ($ImagePath -match '^\s*"([^"]+)"') { return $Matches[1] }
    if ($ImagePath -match '^\s*(.+?\.exe)\b') { return $Matches[1] }
    return $null
}

function Stop-ProcessSafe($Process) {
    if ($Process.Id -eq $PID) { return }
    try {
        Stop-Process -Id $Process.Id -Force -ErrorAction Stop
        Write-Log "Killed process $($Process.ProcessName) (PID $($Process.Id))" OK
    } catch {
        Write-Log "Could not kill $($Process.ProcessName) (PID $($Process.Id)): $($_.Exception.Message)" WARN
    }
}

function Stop-MatchingProcesses([string]$NameRegex, [scriptblock]$PathPredicate) {
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
        if (& $Predicate $k.PSChildName ([string]$k.GetValue('ImagePath'))) { $names.Add($k.PSChildName) }
    }
    return ,$names.ToArray()
}

function Stop-ServiceHard([string]$Name) {
    $key = Get-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -ErrorAction SilentlyContinue
    $exe = if ($key) { Get-ExeFromImagePath ([string]$key.GetValue('ImagePath')) } else { $null }

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

    if ($exe) {
        foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
            $path = $null
            try { $path = $p.Path } catch { }
            if ($path -and $path -eq $exe) { Stop-ProcessSafe $p }
        }
    }
}

function Remove-ServiceHard([string]$Name) {
    & sc.exe delete "$Name" 2>&1 | Out-Null
    switch ($LASTEXITCODE) {
        0       { Write-Log "Deleted service '$Name'" OK }
        1060    { }   # already gone
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
                OldDisplayName  = [string]$k.GetValue('OldDisplayName')
                UninstallString = [string]$k.GetValue('UninstallString')
            }
        }
    }
}

function Test-EntryMatch($Entry, [scriptblock]$Predicate) {
    foreach ($n in $Entry.DisplayName, $Entry.OldDisplayName) {
        if ($n -and (& $Predicate $n)) { return $true }
    }
    return $false
}

function Get-ProductCodes([scriptblock]$Predicate, [string[]]$KnownCodes = @()) {
    $found = @{}
    foreach ($e in Get-UninstallEntries) {
        if (-not (Test-EntryMatch $e $Predicate)) { continue }
        $code = $null
        if ($e.KeyName -match '^\{[0-9A-Fa-f-]{36}\}$') { $code = $e.KeyName.ToUpper() }
        elseif ($e.UninstallString -match '(?i)msiexec.*?(\{[0-9A-F-]{36}\})') { $code = $Matches[1].ToUpper() }
        if ($code) { $found[$code] = $(if ($e.DisplayName) { $e.DisplayName } else { $e.OldDisplayName }) }
    }
    foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products' -ErrorAction SilentlyContinue)) {
        $name = [string]$k.GetValue('ProductName')
        $code = ConvertFrom-PackedGuid $k.PSChildName
        if ($code -and $name -and (& $Predicate $name)) { $found[$code] = $name }
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
    $msiLog = Join-Path $MsiLogDir ('msi_uninstall_{0}.log' -f $ProductCode.Trim('{}'))
    Write-Log "MSI uninstall $ProductCode ($Label), log: $msiLog"
    $p = Start-Process -FilePath "$env:windir\System32\msiexec.exe" -PassThru -WindowStyle Hidden `
        -ArgumentList "/x $ProductCode /qn /norestart REBOOT=ReallySuppress /L*v `"$msiLog`""
    $null = $p.Handle   # needed so ExitCode is populated on PS 5.1
    if (-not $p.WaitForExit(600000)) {
        Write-Log 'msiexec did not finish in 10 minutes - killing it and cleaning up manually' WARN
        try { $p.Kill() } catch { }
        return
    }
    switch ($p.ExitCode) {
        0       { Write-Log 'MSI uninstall succeeded' OK }
        1605    { Write-Log 'MSI says product is not installed - cleaning up leftovers manually' }
        1618    { Write-Log 'Another installation is in progress (1618) - cleaning up manually' WARN }
        { $_ -in 1641, 3010 } { Write-Log 'MSI uninstall succeeded (reboot needed)' OK; $script:RebootRequired = $true }
        default { Write-Log "MSI uninstall failed with exit code $($p.ExitCode) - cleaning up manually" WARN }
    }
}

function Remove-MsiComponentRefs([string]$Packed) {
    # Removes the product from UserData\<sid>\Components (as LabUninstall.exe does).
    # Slow-ish, so it only runs when msiexec failed to unregister the product.
    Write-Log "Scanning Windows Installer component registrations for $Packed..."
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $ud = $hklm.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData')
    if (-not $ud) { $hklm.Close(); return }
    $count = 0
    foreach ($sid in $ud.GetSubKeyNames()) {
        $comps = $ud.OpenSubKey("$sid\Components")
        if (-not $comps) { continue }
        foreach ($c in $comps.GetSubKeyNames()) {
            $ck = $comps.OpenSubKey($c)
            if (-not $ck) { continue }
            $has  = $ck.GetValueNames() -contains $Packed
            $only = $has -and ($ck.ValueCount -eq 1) -and ($ck.SubKeyCount -eq 0)
            $ck.Close()
            if (-not $has) { continue }
            try {
                if ($only) { $w = $ud.OpenSubKey("$sid\Components", $true); $w.DeleteSubKey($c) }
                else       { $w = $ud.OpenSubKey("$sid\Components\$c", $true); $w.DeleteValue($Packed) }
                $w.Close()
                $count++
            } catch { Write-Log "Could not clean component ${c}: $($_.Exception.Message)" WARN }
        }
        $comps.Close()
    }
    $ud.Close(); $hklm.Close()
    if ($count -gt 0) { Write-Log "Removed $count component reference(s)" OK }
}

function Remove-MsiLeftovers([string]$ProductCode) {
    $packed = ConvertTo-PackedGuid $ProductCode
    if (-not $packed) { return }
    $ProductCode = ConvertFrom-PackedGuid $packed   # normalise to {UPPERCASE}

    $udProducts = @(
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData' -ErrorAction SilentlyContinue |
            ForEach-Object { "$($_.PSPath)\Products\$packed" } |
            Where-Object { Test-Path -LiteralPath $_ }
    )
    $stillRegistered = (Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Installer\Products\$packed") -or ($udProducts.Count -gt 0)

    if ($stillRegistered) {
        Write-Log "Windows Installer still has $ProductCode registered - removing it manually"
        foreach ($p in $udProducts) {   # cached MSI in C:\Windows\Installer
            $lp = [string](Get-ItemProperty -LiteralPath "$p\InstallProperties" -ErrorAction SilentlyContinue).LocalPackage
            if ($lp -and $lp -like "$env:windir\Installer\*.msi") { Remove-PathSafe $lp }
        }
        Remove-MsiComponentRefs $packed
        Remove-RegKeySafe "HKLM:\SOFTWARE\Classes\Installer\Products\$packed"
        Remove-RegKeySafe "HKLM:\SOFTWARE\Classes\Installer\Features\$packed"
        foreach ($p in $udProducts) { Remove-RegKeySafe $p }
        foreach ($ucRoot in 'HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes',
                            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes') {
            foreach ($uc in @(Get-ChildItem -LiteralPath $ucRoot -ErrorAction SilentlyContinue)) {
                if ($uc.GetValueNames() -notcontains $packed) { continue }
                if ($uc.ValueCount -le 1) { Remove-RegKeySafe $uc.PSPath }
                else { Remove-ItemProperty -LiteralPath $uc.PSPath -Name $packed -Force -ErrorAction SilentlyContinue }
            }
        }
    }

    Remove-RegKeySafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
    Remove-RegKeySafe "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
    Remove-RegKeySafe "HKLM:\SOFTWARE\Classes\Installer\Dependencies\$ProductCode"
    Remove-PathPatterns -Patterns @("$env:ProgramData\Package Cache\$ProductCode*")
}

function Remove-ArpEntries([scriptblock]$Predicate) {
    foreach ($e in Get-UninstallEntries) {
        if (Test-EntryMatch $e $Predicate) { Remove-RegKeySafe $e.Key }
    }
}

function Remove-MatchingScheduledTasks([scriptblock]$Predicate) {
    # Reads task XML straight from disk - no COM/CIM, locale-independent
    $root = Join-Path $env:windir 'System32\Tasks'
    foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        $xml = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $xml -or -not (& $Predicate $xml)) { continue }
        $tn = $f.FullName.Substring($root.Length)
        & schtasks.exe /Delete /TN "$tn" /F 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Log "Deleted scheduled task: $tn" OK }
        else { Write-Log "Failed to delete scheduled task: $tn" WARN }
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
        try { Remove-NetFirewallRule -Name $id -ErrorAction Stop }
        catch { Remove-ItemProperty -LiteralPath $key -Name $id -Force -ErrorAction SilentlyContinue }
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
$script:LtBasePaths  = @("$env:windir\LTSvc")   # + BasePath from the registry at runtime
$script:LtExtraCodes = @()                      # + branded product code from Update.ini
$script:LtTrayPort   = $null
$LtServiceNames = @('LTService', 'LTSvcMon', 'LTServiceMon', 'LabVNC')
$LtPathPredicate = {
    param($p)
    if (-not $p) { return $false }
    if ($p -match '\\LTSvc\\') { return $true }
    foreach ($b in $script:LtBasePaths) { if ($p.IndexOf("$b\", [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true } }
    return $false
}
$LtSvcPredicate     = { param($name, $image) ($LtServiceNames -contains $name) -or (& $LtPathPredicate $image) }
$LtProductPredicate = { param($n) ($n -match 'LabTech|ConnectWise Automate') -and ($n -match 'Agent|Remote') -and ($n -notmatch 'Control Center') }
$LtTextPredicate    = { param($t) ($t -match '\\LTSvc\\|LTTray|LabTech Agent|LabTech\\Service') -or (& $LtPathPredicate $t) }
$LtProcessRegex     = '^(LTSVC|LTSvcMon|LTServiceMon|LTTray|LabVNC)$'
$LtKnownCodes = @(
    '{58A3001D-B675-4D67-A5A1-0FA9F08CF7CA}',   # agent MSI
    '{3F460D4C-D217-46B4-80B6-B5ED50BD7CF5}',   # agent MSI
    '{206A1CA5-EB86-400E-8B60-B27869F18501}',   # the rest: Installer\Dependencies / Package Cache
    '{04DEC523-746F-4527-B75F-141E3CB0D0AA}',   #   entries that LabUninstall.exe cleans
    '{A7E919B0-AB60-4BA7-A4E5-E1C87E23A5BF}'
)
$LtTempItems   = @('LabTech', '_LTUpdate', 'LTUpdate', 'LTCache', 'LTApp', 'LTErrors.txt')
$LtRegSubKeys  = @('Service', 'Tray', 'Probe', 'ProbeService', 'Plugins')
$LtTracingKeys = @(
    'LabtechRemoteAgentAutoInstall_RASAPI32', 'LabtechRemoteAgentAutoInstall_RASMANCS',
    'LTSVC_RASAPI32', 'LTSVC_RASMANCS', 'LTSvcMon_RASAPI32', 'LTvcMon_RASAPI32', 'LTSvcMon_RASMANCS'
)
$LtFirewallRuleNames = @(
    'Allow NetFasTalk', 'Allow Local VNC', 'Allow Local Redir', 'Allow Tunnel StunRelay',
    'Allow Tunnel', 'AgentService', 'AgentMonitor', 'AgentTray'
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
$ScSharedFolders = @(   # only removed when removing ALL instances
    "$env:windir\Temp\ScreenConnect",
    "$env:windir\SystemTemp\ScreenConnect"
)

#endregion

#region ---------- Automate removal ----------

function Initialize-AutomatePaths {
    # Read where the agent lives, its tray port and any branded product code BEFORE the registry is wiped
    $protected = @($env:windir, "$env:windir\System32", $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, "$env:SystemDrive\") |
        Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }
    foreach ($k in 'HKLM:\SOFTWARE\LabTech\Service', 'HKLM:\SOFTWARE\WOW6432Node\LabTech\Service') {
        $props = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        if ($props.BasePath) {
            $bp = [Environment]::ExpandEnvironmentVariables([string]$props.BasePath).TrimEnd('\')
            if ($bp -match '^[A-Za-z]:\\[^\\]+' -and $protected -notcontains $bp -and $script:LtBasePaths -notcontains $bp) {
                $script:LtBasePaths += $bp
                Write-Log "Agent base path from registry: $bp"
            }
        }
        $tp = 0
        if ($props.TrayPort -and [int]::TryParse([string]$props.TrayPort, [ref]$tp) -and $tp -gt 0 -and $tp -lt 65536) { $script:LtTrayPort = $tp }
    }
    foreach ($b in $script:LtBasePaths) {
        $ini = Join-Path $b 'Update.ini'
        if (-not (Test-Path -LiteralPath $ini)) { continue }
        foreach ($line in @(Get-Content -LiteralPath $ini -ErrorAction SilentlyContinue)) {
            if ($line -match '^\s*AddremoveGuid\s*=\s*\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}?') {
                $g = '{' + $Matches[1].ToUpper() + '}'
                if ($script:LtExtraCodes -notcontains $g) { $script:LtExtraCodes += $g; Write-Log "Custom product code from Update.ini: $g" }
            }
        }
    }
}

function Remove-AutomateFirewallRules {
    $netsh = "$env:windir\System32\netsh.exe"
    foreach ($n in $LtFirewallRuleNames) {
        $p = Start-Process -FilePath $netsh -ArgumentList "advfirewall firewall delete rule name=`"$n`"" -Wait -PassThru -WindowStyle Hidden
        if ($p.ExitCode -eq 0) { Write-Log "Deleted firewall rule: $n" OK }
    }
    $legacy = @('tcp 4996', 'tcp 4997', 'tcp 4998', 'tcp 4999', 'udp 162')
    if ($script:LtTrayPort) { $legacy += "udp $($script:LtTrayPort)" }
    foreach ($l in $legacy) {
        Start-Process -FilePath $netsh -ArgumentList "firewall delete portopening $l" -Wait -WindowStyle Hidden
    }
    Remove-MatchingFirewallRules { param($d) & $LtPathPredicate $d }
}

function Reset-AutomatePatchingSettings {
    if (-not $ResetWindowsUpdate) { Write-Log 'Windows Update reset is turned off in the configuration'; return }
    Write-Log 'Reverting Windows Update settings changed by Automate patch management'
    $wuValueNames = @(
        'ElevateNonAdmins', 'TargetGroup', 'TargetGroupEnabled', 'WUServer', 'WUStatusServer',
        'DisableWindowsUpdateAccess', 'NoAutoUpdate', 'UseWUServer', 'NoAutoRebootWithLoggedOnUsers', 'AUOptions'
    )
    foreach ($k in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
                   'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
                   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update') {
        Remove-RegValuesMatching $k { param($n, $d) $wuValueNames -contains $n }
    }

    $scKey = 'HKLM:\SOFTWARE\Microsoft\Security Center'
    if ((Get-ItemProperty -LiteralPath $scKey -Name UpdatesDisableNotify -ErrorAction SilentlyContinue).UpdatesDisableNotify) {
        Set-ItemProperty -LiteralPath $scKey -Name UpdatesDisableNotify -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Write-Log 'Set Security Center UpdatesDisableNotify = 0' OK
    }
    Remove-RegValuesMatching 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' { param($n, $d) $n -eq 'HideSCAHealth' }

    # Automate disables the Update Orchestrator service while it manages patching
    $uso = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc' -Name Start -ErrorAction SilentlyContinue
    if ($uso -and $uso.Start -eq 4) {
        & sc.exe config UsoSvc start= delayed-auto 2>&1 | Out-Null
        & sc.exe failure UsoSvc reset= 86400 actions= restart/120000/restart/120000 2>&1 | Out-Null
        Write-Log 'Re-enabled Update Orchestrator service (UsoSvc)' OK
    }
}

function Invoke-AutomateRemoval {
    Write-Section 'ConnectWise Automate agent'

    # Same safety checks as LabUninstall.exe
    $isServer = (Test-Path "$env:ProgramFiles\LabTech\LTAgent.exe") -or
                (${env:ProgramFiles(x86)} -and (Test-Path "${env:ProgramFiles(x86)}\LabTech\LTAgent.exe")) -or
                (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LabMySQL') -or
                (Test-Path "$env:SystemDrive\inetpub\wwwroot\LabTech\bin\LabTech.dll") -or
                (Test-Path "$env:SystemDrive\inetpub\wwwroot\WCC2\bin\LabTech Web.dll")
    if ($isServer) {
        Write-Log 'This machine looks like an Automate SERVER - skipping Automate removal.' WARN
        $script:SkippedServer = $true
        return
    }
    $hasControlCenter = (Test-Path "$env:ProgramFiles\LabTech Client\LTClient.exe") -or
                        (${env:ProgramFiles(x86)} -and (Test-Path "${env:ProgramFiles(x86)}\LabTech Client\LTClient.exe"))
    if ($hasControlCenter) { Write-Log 'Automate Control Center found - keeping its folder and settings' }

    Initialize-AutomatePaths

    # 1. Stop everything
    $services = Get-ServiceNamesMatching $LtSvcPredicate
    Write-Log ('Services found: {0}' -f $(if ($services) { $services -join ', ' } else { 'none' }))
    foreach ($s in $services) { Stop-ServiceHard $s }
    Stop-MatchingProcesses -NameRegex $LtProcessRegex -PathPredicate $LtPathPredicate

    # 2. MSI uninstall
    $codes = Get-ProductCodes -Predicate $LtProductPredicate -KnownCodes ($LtKnownCodes + $script:LtExtraCodes)
    if ($codes.Count -eq 0) { Write-Log 'No Automate agent MSI registration found' }
    foreach ($code in @($codes.Keys)) { Invoke-MsiUninstall $code $codes[$code] }
    Stop-MatchingProcesses -NameRegex $LtProcessRegex -PathPredicate $LtPathPredicate

    # 3. Clean up
    foreach ($b in $script:LtBasePaths) {
        $dll = Join-Path $b 'wodVpn.dll'
        if (Test-Path -LiteralPath $dll) {
            Start-Process -FilePath "$env:windir\System32\regsvr32.exe" -ArgumentList "/u /s `"$dll`"" -Wait -WindowStyle Hidden
            Write-Log "Unregistered $dll" OK
        }
    }

    foreach ($s in (Get-ServiceNamesMatching $LtSvcPredicate)) { Remove-ServiceHard $s }
    $allCodes = @(@($codes.Keys) + $LtKnownCodes + $script:LtExtraCodes | ForEach-Object { $_.ToUpper() } | Sort-Object -Unique)
    foreach ($code in $allCodes) { Remove-MsiLeftovers $code }
    Remove-ArpEntries $LtProductPredicate

    $paths = @($script:LtBasePaths)
    foreach ($t in "$env:windir\Temp", "$env:windir\SystemTemp") {
        foreach ($i in $LtTempItems) { $paths += Join-Path $t $i }
    }
    $paths += "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\Network Monitoring Tray.lnk"
    if (-not $hasControlCenter) { $paths += "$env:ProgramData\LabTech" }
    Remove-PathPatterns -Patterns $paths

    foreach ($root in 'HKLM:\SOFTWARE\LabTech', 'HKLM:\SOFTWARE\WOW6432Node\LabTech') {
        if ($hasControlCenter) { foreach ($sk in $LtRegSubKeys) { Remove-RegKeySafe "$root\$sk" } }
        else { Remove-RegKeySafe $root }
    }
    Remove-RegKeySafe 'HKLM:\SOFTWARE\LabTechMSP'
    Remove-RegKeySafe 'HKLM:\SOFTWARE\WOW6432Node\LabTechMSP'
    if (-not $hasControlCenter) {
        foreach ($sid in Get-LoadedUserHives) { Remove-RegKeySafe "Registry::HKEY_USERS\$sid\SOFTWARE\LabTech" }
    }
    foreach ($t in $LtTracingKeys) {
        Remove-RegKeySafe "HKLM:\SOFTWARE\Microsoft\Tracing\$t"
        Remove-RegKeySafe "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Tracing\$t"
    }
    Remove-RegKeySafe 'HKLM:\SOFTWARE\Sysinternals'
    Remove-RegKeySafe 'HKLM:\SOFTWARE\WOW6432Node\Sysinternals'
    # LabVNC is UltraVNC-based - keep these keys if a standalone UltraVNC is installed
    $uvnc = (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\uvnc_service') -or
            (Test-Path "$env:ProgramFiles\uvnc bvba") -or
            (${env:ProgramFiles(x86)} -and (Test-Path "${env:ProgramFiles(x86)}\uvnc bvba"))
    if ($uvnc) { Write-Log 'Standalone UltraVNC found - keeping UltraVNC/ORL registry keys' }
    else { Remove-RegKeySafe 'HKLM:\SOFTWARE\UltraVNC'; Remove-RegKeySafe 'HKLM:\SOFTWARE\ORL' }

    Remove-RegChildren 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application' { param($n) ($LtServiceNames -contains $n) -or ($n -match '^LabTech') }
    # tvnserver = TightVNC; only drop its Safe Mode entry if no TightVNC service is left
    $safeBootNames = @($LtServiceNames)
    if (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\tvnserver')) { $safeBootNames += 'tvnserver' }
    foreach ($mode in 'Minimal', 'Network') {
        Remove-RegChildren "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode" { param($n) $safeBootNames -contains $n }
    }

    foreach ($rk in Get-RunKeys) {
        Remove-RegValuesMatching $rk { param($n, $d) ($n -eq 'LabTech Tray Icon') -or (& $LtTextPredicate $d) }
    }
    Remove-MatchingScheduledTasks $LtTextPredicate
    Remove-AutomateFirewallRules
    Reset-AutomatePatchingSettings
}

#endregion

#region ---------- ScreenConnect removal ----------

function Invoke-ScreenConnectRemoval {
    Write-Section 'ScreenConnect / ConnectWise Control client'
    if ($script:ScThumbs.Count) { Write-Log ('Only removing instance(s): {0}' -f ($script:ScThumbs -join ', ')) }
    else { Write-Log 'Removing ALL ScreenConnect / ConnectWise Control client instances' }

    # 1. Stop everything
    $services = Get-ServiceNamesMatching $ScSvcPredicate
    Write-Log ('Services found: {0}' -f $(if ($services) { $services -join ', ' } else { 'none' }))
    foreach ($s in $services) { Stop-ServiceHard $s }
    Stop-MatchingProcesses -NameRegex $ScProcessRegex -PathPredicate $ScPathPredicate

    # 2. MSI uninstall
    $codes = Get-ProductCodes -Predicate $ScProductPredicate
    if ($codes.Count -eq 0) { Write-Log 'No ScreenConnect MSI registration found' }
    foreach ($code in @($codes.Keys)) { Invoke-MsiUninstall $code $codes[$code] }
    Stop-MatchingProcesses -NameRegex $ScProcessRegex -PathPredicate $ScPathPredicate

    # 3. Clean up
    foreach ($s in (Get-ServiceNamesMatching $ScSvcPredicate)) { Remove-ServiceHard $s }
    foreach ($code in @($codes.Keys)) { Remove-MsiLeftovers $code }
    Remove-ArpEntries $ScProductPredicate

    # Credential providers / filters loaded from a ScreenConnect DLL
    foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers',
                      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters') {
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

    # LSA packages that reference ScreenConnect (only when removing all instances)
    if ($script:ScThumbs.Count -eq 0) {
        $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        foreach ($vn in 'Authentication Packages', 'Security Packages', 'Notification Packages') {
            $vals = @((Get-ItemProperty -LiteralPath $lsa -Name $vn -ErrorAction SilentlyContinue).$vn | Where-Object { $_ })
            $keep = [string[]]@($vals | Where-Object { $_ -notmatch 'ScreenConnect' })
            if ($keep.Count -lt $vals.Count) {
                Set-ItemProperty -LiteralPath $lsa -Name $vn -Value $keep -Type MultiString
                Write-Log "Removed ScreenConnect entry from LSA '$vn'" OK
                $script:RebootRequired = $true
            }
        }
    }

    # Folders (machine-wide and per user profile)
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

#endregion

#region ---------- Verification ----------

function Get-Leftovers {
    $left = New-Object System.Collections.Generic.List[string]
    if ($RemoveAutomate -and -not $script:SkippedServer) {
        foreach ($s in (Get-ServiceNamesMatching $LtSvcPredicate)) { $left.Add("Service: $s") }
        foreach ($f in $script:LtBasePaths) {
            if ((Test-Path -LiteralPath $f) -and -not (Test-PendingDelete $f)) { $left.Add("Folder: $f") }
        }
        foreach ($e in Get-UninstallEntries) {
            if (Test-EntryMatch $e $LtProductPredicate) { $left.Add("Programs entry: $($e.DisplayName)$($e.OldDisplayName)") }
        }
    }
    if ($RemoveScreenConnect) {
        foreach ($s in (Get-ServiceNamesMatching $ScSvcPredicate)) { $left.Add("Service: $s") }
        foreach ($pat in $ScFolders) {
            if (-not $pat -or $pat -match '^\\') { continue }
            foreach ($i in @(Get-Item -Path $pat -Force -ErrorAction SilentlyContinue)) {
                if ((Test-ScMatch $i.Name) -and -not (Test-PendingDelete $i.FullName)) { $left.Add("Folder: $($i.FullName)") }
            }
        }
        foreach ($e in Get-UninstallEntries) {
            if (Test-EntryMatch $e $ScProductPredicate) { $left.Add("Programs entry: $($e.DisplayName)$($e.OldDisplayName)") }
        }
    }
    return ,$left.ToArray()
}

#endregion

#region ---------- Main ----------

$script:SkippedServer = $false
Write-Section 'ConnectWise Automate + ScreenConnect removal (Intune)'
Write-Log "Computer: $env:COMPUTERNAME  Account: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"

# Automate first: it can re-deploy ScreenConnect while it's still running
if ($RemoveAutomate)      { Invoke-AutomateRemoval }
if ($RemoveScreenConnect) { Invoke-ScreenConnectRemoval }

Write-Section 'Result'
$leftovers = Get-Leftovers
foreach ($l in $leftovers) { Write-Log "Still present: $l" ERROR }

if ($leftovers.Count -gt 0) {
    Write-Log "$($leftovers.Count) item(s) could not be removed - exiting 1 so Intune retries." ERROR
    exit 1
}
if ($script:RebootRequired) {
    Write-Log 'Removal complete. Locked items will be deleted at the next reboot.' WARN
} else {
    Write-Log 'Removal complete.' OK
}
exit 0

#endregion
