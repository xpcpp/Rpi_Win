<#
 bootstrap.ps1 - one-time setup of the Pi agent. Run from an ELEVATED PowerShell:
   iwr -UseBasicParsing https://raw.githubusercontent.com/xpcpp/Rpi_Win/<commit>/agent/bootstrap.ps1 -OutFile bootstrap.ps1
   .\bootstrap.ps1
 It asks for a GitHub *fine-grained* token limited to repo xpcpp/Rpi_Win with:  Issues: read/write  (and Contents: read).
 Do NOT use the token you gave in chat; create a new minimal one for the Pi.
#>
param(
  [string]$Repo = 'xpcpp/Rpi_Win',
  [int]$Issue = 0,
  [string]$Commit = 'main'
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from an elevated PowerShell.' }
if ($Issue -le 0) { $Issue = [int](Read-Host 'Issue number of the "agent log" issue') }

$Root = 'C:\rpiwin-agent'
New-Item -ItemType Directory -Force $Root | Out-Null
$sec = Read-Host 'Paste the fine-grained GitHub token for the Pi (input hidden)' -AsSecureString
$tok = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
Set-Content (Join-Path $Root 'token.txt') $tok -NoNewline
@{ repo = $Repo; issue = $Issue } | ConvertTo-Json | Set-Content (Join-Path $Root 'config.json')

# commands already in the repo are treated as done, so a re-install can never replay old ones (e.g. reboot)
try {
  $hh = @{ Authorization = "Bearer $tok"; Accept = 'application/vnd.github+json'; 'User-Agent' = 'rpiwin-bootstrap' }
  $existing = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/contents/agent/commands" -Headers $hh -UseBasicParsing
  ($existing | Where-Object { $_.name -like '*.json' } | ForEach-Object { $_.name }) | Set-Content (Join-Path $Root 'done.txt')
} catch { Set-Content (Join-Path $Root 'done.txt') '' }

# only SYSTEM + Administrators may read the folder (the token lives there)
icacls $Root /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

# fetch the agent itself
$h = @{ Authorization = "Bearer $tok"; Accept = 'application/vnd.github.raw'; 'User-Agent' = 'rpiwin-bootstrap' }
Invoke-WebRequest -UseBasicParsing -Headers $h -Uri "https://api.github.com/repos/$Repo/contents/agent/agent.ps1?ref=$Commit" -OutFile (Join-Path $Root 'agent.ps1')

# scheduled task: at startup + every minute, as SYSTEM
$act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Root\agent.ps1`""
$t1  = New-ScheduledTaskTrigger -AtStartup
$t2  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$set = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
$pri = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Unregister-ScheduledTask -TaskName 'rpiwin-agent' -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName 'rpiwin-agent' -Action $act -Trigger @($t1,$t2) -Settings $set -Principal $pri | Out-Null
Start-ScheduledTask -TaskName 'rpiwin-agent'
Write-Host 'Agent installed. It posts a BOOT REPORT to the issue within about a minute.'
Write-Host 'Remove it any time with:  Unregister-ScheduledTask rpiwin-agent -Confirm:$false; Remove-Item C:\rpiwin-agent -Recurse -Force'
