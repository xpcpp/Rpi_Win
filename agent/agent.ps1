<#
 agent.ps1 - GitHub-polling agent for the Pi (runs as SYSTEM from a Scheduled Task every minute).

 * Reads agent/commands/*.json from the repo (GitHub API), runs ONLY allow-listed actions, posts the output
   as a comment on the "agent log" issue. No inbound ports, no arbitrary command execution.
 * On every boot it posts a boot report (device state, probe registry, last bugcheck).
 * Crash-loop safety: a bugcheck within 15 min of boot => the sdioprobe service is disabled automatically.

 Allowed actions: status, info, probe, diag, rearm, bugcheck, install (-Only all|sdhc|sdiofn), cleanup,
                  disable-probe, enable-probe, reboot, ping
#>
$ErrorActionPreference = 'Continue'
$Root = 'C:\rpiwin-agent'
$cfg  = Get-Content (Join-Path $Root 'config.json') -Raw | ConvertFrom-Json
$Repo = $cfg.repo; $IssueNo = $cfg.issue
$Token = (Get-Content (Join-Path $Root 'token.txt') -Raw).Trim()
$DonePath = Join-Path $Root 'done.txt'
$LastBootPath = Join-Path $Root 'lastboot.txt'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# single instance
$mutex = New-Object System.Threading.Mutex($false, 'Global\rpiwin-agent')
if (-not $mutex.WaitOne(0)) { exit 0 }

function Invoke-Gh([string]$Method, [string]$Path, $Body = $null, [string]$Accept = 'application/vnd.github+json') {
  $h = @{ Authorization = "Bearer $Token"; Accept = $Accept; 'User-Agent' = 'rpiwin-agent'; 'X-GitHub-Api-Version' = '2022-11-28' }
  $u = "https://api.github.com/repos/$Repo/$Path"
  if ($Body -ne $null) { return Invoke-RestMethod -Uri $u -Method $Method -Headers $h -Body ($Body | ConvertTo-Json -Depth 5) -ContentType 'application/json' -UseBasicParsing }
  return Invoke-RestMethod -Uri $u -Method $Method -Headers $h -UseBasicParsing
}

function Post-Comment([string]$Title, [string]$Text) {
  if ($Text.Length -gt 60000) { $Text = $Text.Substring(0, 30000) + "`n...[truncated]...`n" + $Text.Substring($Text.Length - 28000) }
  $body = "**$Title**  ($env:COMPUTERNAME, $(Get-Date -Format s))`n``````text`n$Text`n``````"
  try { Invoke-Gh 'POST' "issues/$IssueNo/comments" @{ body = $body } | Out-Null } catch { Add-Content (Join-Path $Root 'agent.log') "post failed: $($_.Exception.Message)" }
}

function Get-File([string]$RepoPath, [string]$Dest) {
  $raw = Invoke-Gh 'GET' "contents/$RepoPath" $null 'application/vnd.github.raw'
  if ($raw -is [string]) { [IO.File]::WriteAllText($Dest, $raw, (New-Object Text.UTF8Encoding($true))) } else { $raw | ConvertTo-Json -Depth 8 | Set-Content $Dest }
}

function Run-PiTest([string]$Action, [string[]]$Extra = @()) {
  $script = Join-Path $Root 'pi-test.ps1'
  Get-File 'scripts/pi-test.ps1' $script
  $psArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$script,'-Action',$Action) + $Extra
  Push-Location $Root
  try { return (& powershell.exe @psArgs *>&1 | Out-String -Width 200) } finally { Pop-Location }
}

function Handle-Action($cmd) {
  switch ($cmd.action) {
    'ping'          { return "pong from $env:COMPUTERNAME, uptime since " + (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
    'status'        { return Run-PiTest 'Status' }
    'info'          { return Run-PiTest 'Info' }
    'probe'         { return Run-PiTest 'Probe' }
    'diag'          { return Run-PiTest 'Diag' }
    'bugcheck'      { return Run-PiTest 'Bugcheck' }
    'rearm'         { return Run-PiTest 'Rearm' }
    'cleanup'       { return Run-PiTest 'Cleanup' }
    'install'       {
      $only = if ($cmd.only -in 'all','sdhc','sdiofn') { $cmd.only } else { 'sdiofn' }
      return Run-PiTest 'Install' @('-Only', $only, '-Yes')
    }
    'disable-probe' { return (sc.exe config sdioprobe start= disabled | Out-String) }
    'enable-probe'  { return (sc.exe config sdioprobe start= demand   | Out-String) }
    'reboot'        { return 'REBOOT' }
    default         { return "refused: action '$($cmd.action)' is not allow-listed" }
  }
}

# ---------- boot report + crash-loop safety ----------
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('s')
$prevBoot = if (Test-Path $LastBootPath) { (Get-Content $LastBootPath -Raw).Trim() } else { '' }
if ($boot -ne $prevBoot) {
  Set-Content $LastBootPath $boot
  $report = ''
  $bc = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001; StartTime=(Get-Date).AddMinutes(-15)} -ErrorAction SilentlyContinue
  if ($bc) {
    $svc = (sc.exe qc sdioprobe 2>&1 | Out-String)
    if ($svc -notmatch 'DISABLED') {
      sc.exe config sdioprobe start= disabled | Out-Null
      $report += "CRASH-LOOP SAFETY: bugcheck within 15 min of boot -> sdioprobe service disabled.`n`n"
    }
  }
  $report += Run-PiTest 'Diag'
  Post-Comment "BOOT REPORT (boot $boot)" $report
}

# ---------- commands ----------
$done = @(); if (Test-Path $DonePath) { $done = @(Get-Content $DonePath) }
try { $list = Invoke-Gh 'GET' 'contents/agent/commands' } catch { exit 0 }
foreach ($f in ($list | Where-Object { $_.name -like '*.json' } | Sort-Object name)) {
  if ($done -contains $f.name) { continue }
  Add-Content $DonePath $f.name                       # mark first: a command that crashes the box must not repeat
  $tmp = Join-Path $Root 'cmd.json'
  Get-File ("agent/commands/" + $f.name) $tmp
  try { $cmd = Get-Content $tmp -Raw | ConvertFrom-Json } catch { Post-Comment "COMMAND $($f.name)" "invalid json"; continue }
  $out = Handle-Action $cmd
  if ($out -eq 'REBOOT') {
    Post-Comment "COMMAND $($f.name): reboot" "rebooting in 5 s"
    shutdown.exe /r /t 5 /f
    break
  }
  Post-Comment "COMMAND $($f.name): $($cmd.action)" $out
}
