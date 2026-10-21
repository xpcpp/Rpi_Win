<#
 agent.ps1 v2 - GitHub-polling agent for the Pi. Runs as SYSTEM from a Scheduled Task (at boot + every minute as a watchdog).

 * Long-running loop: checks agent/commands every ~4 s (conditional requests with ETag => no rate-limit cost).
 * Runs allow-listed actions, plus 'ps' (arbitrary PowerShell) ONLY while the repo contains the file agent/DEV_MODE.
 * Posts "started" and result comments on the agent-log issue. Boot report is retried until it is really posted.
 * Self-update: when agent/agent.ps1 changes in the repo the new version is syntax-checked, swapped in, and the agent restarts.
 * Crash-loop safety: a bugcheck within 15 min of boot => the sdioprobe service is disabled.
#>
$ErrorActionPreference = 'Continue'
$Root = 'C:\rpiwin-agent'
$Work = Join-Path $Root 'work'
New-Item -ItemType Directory -Force $Work | Out-Null
$cfg  = Get-Content (Join-Path $Root 'config.json') -Raw | ConvertFrom-Json
$Repo = $cfg.repo; $IssueNo = $cfg.issue
$Token = (Get-Content (Join-Path $Root 'token.txt') -Raw).Trim()
$DonePath = Join-Path $Root 'done.txt'
$LastBootPath = Join-Path $Root 'lastboot.txt'
$LogPath = Join-Path $Root 'agent.log'
$AgentVersion = 'v2'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$mutex = New-Object System.Threading.Mutex($false, 'Global\rpiwin-agent')
if (-not $mutex.WaitOne(0)) { exit 0 }

function Log([string]$m) { Add-Content $LogPath ("{0} {1}" -f (Get-Date -Format s), $m) }

function Gh-Headers([string]$Accept = 'application/vnd.github+json') {
  return @{ Authorization = "Bearer $Token"; Accept = $Accept; 'User-Agent' = 'rpiwin-agent'; 'X-GitHub-Api-Version' = '2022-11-28' }
}

function Invoke-Gh([string]$Method, [string]$Path, $Body = $null, [string]$Accept = 'application/vnd.github+json') {
  $u = "https://api.github.com/repos/$Repo/$Path"
  if ($Body -ne $null) {
    return Invoke-RestMethod -Uri $u -Method $Method -Headers (Gh-Headers $Accept) -Body ($Body | ConvertTo-Json -Depth 5) -ContentType 'application/json' -UseBasicParsing
  }
  return Invoke-RestMethod -Uri $u -Method $Method -Headers (Gh-Headers $Accept) -UseBasicParsing
}

# conditional GET: returns $null when nothing changed (HTTP 304)
function Get-GhJson([string]$Path, [ref]$Etag) {
  $h = Gh-Headers
  if ($Etag.Value) { $h['If-None-Match'] = $Etag.Value }
  try {
    $r = Invoke-WebRequest -Uri "https://api.github.com/repos/$Repo/$Path" -Headers $h -UseBasicParsing
    $Etag.Value = [string]$r.Headers['ETag']
    return ($r.Content | ConvertFrom-Json)
  } catch {
    $resp = $_.Exception.Response
    if ($resp -and [int]$resp.StatusCode -eq 304) { return $null }
    throw
  }
}

function Post-Comment([string]$Title, [string]$Text) {
  if ($Text.Length -gt 60000) { $Text = $Text.Substring(0, 30000) + "`n...[truncated]...`n" + $Text.Substring($Text.Length - 28000) }
  $body = "**$Title**  ($env:COMPUTERNAME, $(Get-Date -Format s))`n``````text`n$Text`n``````"
  try { Invoke-Gh 'POST' "issues/$IssueNo/comments" @{ body = $body } | Out-Null; return $true }
  catch { Log "post failed: $($_.Exception.Message)"; return $false }
}

function Get-File([string]$RepoPath, [string]$Dest) {
  $raw = Invoke-Gh 'GET' "contents/$RepoPath" $null 'application/vnd.github.raw'
  if ($raw -is [string]) { [IO.File]::WriteAllText($Dest, $raw, (New-Object Text.UTF8Encoding($true))) }
  else { $raw | ConvertTo-Json -Depth 8 | Set-Content $Dest }
}

function Run-PiTest([string]$Action, [string[]]$Extra = @()) {
  $script = Join-Path $Root 'pi-test.ps1'
  try { Get-File 'scripts/pi-test.ps1' $script } catch { Log "pi-test download failed, using cached copy: $($_.Exception.Message)" }
  if (-not (Test-Path $script)) { return 'pi-test.ps1 not available' }
  $psArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$script,'-Action',$Action) + $Extra
  Push-Location $Root
  try { return (& powershell.exe @psArgs *>&1 | Out-String -Width 200) } finally { Pop-Location }
}

function Test-DevMode {
  try { Invoke-Gh 'GET' 'contents/agent/DEV_MODE' | Out-Null; return $true } catch { return $false }
}

function Run-DevPs($cmd) {
  if (-not (Test-DevMode)) { return "refused: DEV_MODE is off (file agent/DEV_MODE is missing in the repo)" }
  $script = [string]$cmd.script
  if (-not $script) { return 'ps: no "script" given' }
  $timeout = 120
  if ($cmd.timeout_sec) { $timeout = [Math]::Min([int]$cmd.timeout_sec, 600) }
  $f = Join-Path $Work 'dev.ps1'; $o = Join-Path $Work 'dev.out'; $e = Join-Path $Work 'dev.err'
  Remove-Item $o,$e -ErrorAction SilentlyContinue
  Set-Content $f $script -Encoding UTF8
  $p = Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$f) `
        -RedirectStandardOutput $o -RedirectStandardError $e -PassThru -WindowStyle Hidden -WorkingDirectory $Work
  if (-not $p.WaitForExit($timeout * 1000)) { try { $p.Kill() } catch {}; $tmo = "`n[TIMEOUT after $timeout s - process killed]" } else { $tmo = '' }
  $out = ''; if (Test-Path $o) { $out = Get-Content $o -Raw }
  $err = ''; if (Test-Path $e) { $err = Get-Content $e -Raw }
  if ($err) { $out += "`n[stderr]`n$err" }
  return ($out + $tmo)
}

function Handle-Action($cmd) {
  switch ($cmd.action) {
    'ping'          { return "pong from $env:COMPUTERNAME (agent $AgentVersion), booted " + (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
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
    'disable-probe' { return ((sc.exe config sdioprobe start= disabled; sc.exe config sdioprobe2 start= disabled) | Out-String) }
    'enable-probe'  { return ((sc.exe config sdioprobe start= demand; sc.exe config sdioprobe2 start= demand) | Out-String) }
    'ps'            { return Run-DevPs $cmd }
    'reboot'        { return 'REBOOT' }
    default         { return "refused: action '$($cmd.action)' is not allow-listed" }
  }
}

# ---------- boot report (retried until posted) + crash-loop safety ----------
function Wait-Network([int]$Seconds = 240) {
  $end = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $end) {
    try { Invoke-Gh 'GET' "issues/$IssueNo" | Out-Null; return $true } catch { Start-Sleep -Seconds 5 }
  }
  return $false
}

function Send-BootReportIfNeeded {
  $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('s')
  $prev = if (Test-Path $LastBootPath) { (Get-Content $LastBootPath -Raw).Trim() } else { '' }
  if ($boot -eq $prev) { return }
  $report = ''
  $bc = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001; StartTime=(Get-Date).AddMinutes(-15)} -ErrorAction SilentlyContinue
  if ($bc) {
    $svc = ((sc.exe qc sdioprobe2 2>&1) + (sc.exe qc sdioprobe 2>&1) | Out-String)
    if ($svc -notmatch 'DISABLED') {
      sc.exe config sdioprobe start= disabled | Out-Null
      sc.exe config sdioprobe2 start= disabled | Out-Null
      $report += "CRASH-LOOP SAFETY: bugcheck within 15 min of boot -> sdioprobe service disabled.`n`n"
    }
  }
  if (-not (Wait-Network 240)) { Log 'boot report: no network yet, will retry'; return }
  $report += Run-PiTest 'Diag'
  if (Post-Comment "BOOT REPORT (boot $boot, agent $AgentVersion)" $report) { Set-Content $LastBootPath $boot }
}

# ---------- self-update ----------
function Get-GitBlobSha([string]$Path) {
  $bytes = [IO.File]::ReadAllBytes($Path)
  $hdr = [Text.Encoding]::ASCII.GetBytes("blob $($bytes.Length)`0")
  $sha = [Security.Cryptography.SHA1]::Create()
  return (($sha.ComputeHash($hdr + $bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Try-SelfUpdate([ref]$Etag) {
  $meta = Get-GhJson 'contents/agent/agent.ps1' $Etag
  if ($meta -eq $null) { return $false }
  $self = Join-Path $Root 'agent.ps1'
  if ($meta.sha -eq (Get-GitBlobSha $self)) { return $false }
  $new = Join-Path $Root 'agent.ps1.new'
  # exact bytes (no BOM, no re-encoding) so the blob SHA of the local copy always equals the repo's
  Invoke-WebRequest -Uri "https://api.github.com/repos/$Repo/contents/agent/agent.ps1" -Headers (Gh-Headers 'application/vnd.github.raw') -UseBasicParsing -OutFile $new
  $t = $null; $e = $null
  [System.Management.Automation.Language.Parser]::ParseFile($new, [ref]$t, [ref]$e) | Out-Null
  if ($e.Count -gt 0) { Log "self-update: new agent has parse errors, not applied"; Remove-Item $new -ErrorAction SilentlyContinue; return $false }
  Copy-Item $self (Join-Path $Root 'agent.ps1.bak') -Force
  Move-Item $new $self -Force
  Log "self-update applied (blob $($meta.sha)); restarting via scheduled task"
  return $true
}

# ---------- main loop ----------
Log "agent $AgentVersion started (pid $PID)"
$cmdEtag = ''; $selfEtag = ''; $lastSelf = [DateTime]::MinValue; $lastBootTry = [DateTime]::MinValue
$longActions = @('install','cleanup','reboot','ps','diag')

while ($true) {
  try {
    if (((Get-Date) - $lastBootTry).TotalSeconds -gt 30) { $lastBootTry = Get-Date; Send-BootReportIfNeeded }

    if (((Get-Date) - $lastSelf).TotalSeconds -gt 120) {
      $lastSelf = Get-Date
      if (Try-SelfUpdate ([ref]$selfEtag)) { Post-Comment 'AGENT UPDATED' "agent.ps1 replaced from repo; restarting"; exit 0 }
    }

    $list = Get-GhJson 'contents/agent/commands' ([ref]$cmdEtag)
    if ($list -ne $null) {
      $done = @(); if (Test-Path $DonePath) { $done = @(Get-Content $DonePath) }
      foreach ($f in ($list | Where-Object { $_.name -like '*.json' } | Sort-Object name)) {
        if ($done -contains $f.name) { continue }
        Add-Content $DonePath $f.name                       # mark first: a command that crashes the box must not repeat
        $tmp = Join-Path $Root 'cmd.json'
        Get-File ("agent/commands/" + $f.name) $tmp
        try { $cmd = Get-Content $tmp -Raw | ConvertFrom-Json } catch { Post-Comment "COMMAND $($f.name)" "invalid json"; continue }
        if ($longActions -contains $cmd.action) { Post-Comment "STARTED $($f.name): $($cmd.action)" "running ..." | Out-Null }
        $out = Handle-Action $cmd
        if ($out -eq 'REBOOT') {
          Post-Comment "COMMAND $($f.name): reboot" "rebooting in 5 s" | Out-Null
          shutdown.exe /r /t 5 /f
          Start-Sleep -Seconds 30
          break
        }
        Post-Comment "COMMAND $($f.name): $($cmd.action)" $out | Out-Null
      }
    }
  } catch { Log "loop error: $($_.Exception.Message)" }
  Start-Sleep -Seconds 4
}
