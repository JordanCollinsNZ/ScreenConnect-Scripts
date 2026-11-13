# SCKit quick IOC check - read-only, runs as standard user (no admin)
# Works in Windows PowerShell 5.1 (and 3.0+) and PowerShell 7.
# Paste the WHOLE script into PowerShell and press Enter (it runs as one block).
& {
  $LegitSuffix = 'aac6a9'   # last 6 chars of our legit SC instance ID
  function New-Check($Name, $Found, $Detail) {
    $o = New-Object PSObject
    $o | Add-Member NoteProperty Check $Name
    $o | Add-Member NoteProperty Result $(if ($Found) { 'FOUND' } else { 'OK' })
    $o | Add-Member NoteProperty Detail $Detail
    $o
  }

  # 1. ScreenConnect client services: count, IDs, start mode
  $svc = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -like 'ScreenConnect Client*' })
  $svcBad = @(foreach ($s in $svc) {
    if ($s.Name -match '2588ef5c15954b10|ed630cc2c873b091') { "KNOWN ROGUE: $($s.Name)" }
    elseif ($s.Name -notmatch "$LegitSuffix\)$") { "Unknown: $($s.Name)" }
    elseif ($s.StartMode -ne 'Auto' -or $s.State -ne 'Running') { "Legit is $($s.StartMode)/$($s.State)" }
  })
  if ($svc.Count -gt 1) { $svcBad += "$($svc.Count) SC services" }

  # 2. Installed ScreenConnect clients
  $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  $apps = @(Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'ScreenConnect Client*' })

  # 3. Run key persistence
  $run = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
  $runHit = [bool]($run -and ($run.PSObject.Properties | Where-Object { $_.Name -eq 'RelayTrapLiteAlert' }))

  # 4. Toolkit files in the user's %TEMP% (C:\Windows\Temp needs admin)
  $pat = '^(sc\.msi|sckit-.*|runnew\.cmd|Panel-Lateral.*\.ps1|ToolboxRelayUploader\.exe|sqlite3\.exe|CWInstall_.*|k[0-9a-f]{32}\.ps1)$'
  $tf = @(Get-ChildItem -LiteralPath $env:TEMP -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $pat })

  $results = @(
    New-Check 'SC services' ($svcBad.Count -gt 0) $(if ($svcBad.Count) { $svcBad -join '; ' } else { "$($svc.Count) service(s), legit Auto/Running" })
    New-Check 'SC installs' ($apps.Count -gt 1) "$($apps.Count) installed"
    New-Check 'RelayTrap.exe process' ([bool](Get-Process -Name RelayTrap -ErrorAction SilentlyContinue)) ''
    New-Check 'C:\ProgramData\RelayTrap' (Test-Path -LiteralPath 'C:\ProgramData\RelayTrap') ''
    New-Check 'RELAY-TRAP-PROOF.txt' (Test-Path -LiteralPath 'C:\Users\Public\RELAY-TRAP-PROOF.txt') ''
    New-Check 'Run key RelayTrapLiteAlert' $runHit ''
    New-Check 'Toolkit files in %TEMP%' ($tf.Count -gt 0) (($tf | ForEach-Object { $_.FullName }) -join '; ')
  )

  # Summary
  Write-Host ''
  Write-Host ("SCKit IOC check - $env:COMPUTERNAME - $env:USERNAME - " + (Get-Date -Format 'yyyy-MM-dd HH:mm')) -ForegroundColor Cyan
  Write-Host ($results | Format-Table -AutoSize -Wrap | Out-String).TrimEnd()
  Write-Host ''
  if (@($results | Where-Object { $_.Result -eq 'OK' -or $_.Result -eq 'FOUND' }).Count -ne 7) { Write-Host 'RESULT: CHECK FAILED - not all checks ran; do the manual checks' -ForegroundColor Yellow; return }
  if (@($results | Where-Object { $_.Result -eq 'FOUND' }).Count) { Write-Host 'RESULT: IOC FOUND - flag immediately to the response team' -ForegroundColor Red }
  else { Write-Host 'RESULT: CLEAN' -ForegroundColor Green }
}