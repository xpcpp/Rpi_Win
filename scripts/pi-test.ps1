<#
 pi-test.ps1 - one-stop helper to test the CI-built bcm2836sdhc driver on the Pi.
 Run from an ELEVATED PowerShell on the Pi (Windows 11 ARM64, test signing ON):

   iwr -UseBasicParsing https://raw.githubusercontent.com/xpcpp/Rpi_Win/main/scripts/pi-test.ps1 -OutFile pi-test.ps1
   .\pi-test.ps1 -Action Install     # download latest CI build, trust its cert, install it
   .\pi-test.ps1 -Action Status      # BCM2847 / SD device state + installed packages
   .\pi-test.ps1 -Action Bugcheck    # decode the last bugcheck (storm-guard registers)
   .\pi-test.ps1 -Action Cleanup     # remove driver package(s) and test certs
#>
param(
  [ValidateSet('Install','Status','Bugcheck','Cleanup')][string]$Action = 'Status',
  [string]$Repo = 'xpcpp/Rpi_Win',
  [string]$Tag  = 'ci-latest',
  [switch]$Yes
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Test-Admin {
  ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Status {
  Write-Host '--- test signing:'
  bcdedit /enum '{current}' | Select-String 'testsigning'
  Write-Host '--- BCM2847 and SD devices:'
  Get-PnpDevice -PresentOnly |
    Where-Object { $_.InstanceId -like 'ACPI\BCM2847*' -or $_.InstanceId -like 'SD\*' } |
    Select-Object Status,Class,FriendlyName,InstanceId | Format-Table -AutoSize -Wrap
  Write-Host '--- installed bcm2836sdhc packages:'
  pnputil /enum-drivers | Select-String -Context 1,6 'bcm2836sdhc'
}

function Remove-SdhcPackages {
  $cur = $null
  pnputil /enum-drivers | ForEach-Object {
    if ($_ -match 'Published Name:\s+(oem\d+\.inf)') { $cur = $Matches[1] }
    if ($_ -match 'Original Name:\s+bcm2836sdhc\.inf' -and $cur) {
      Write-Host "Removing $cur"
      pnputil /delete-driver $cur /uninstall /force | Out-Host
    }
  }
}

function Remove-TestCerts {
  foreach ($store in 'Root','TrustedPublisher') {
    Get-ChildItem "Cert:\LocalMachine\$store" |
      Where-Object { $_.Subject -like 'CN=Rpi_Win CI test signing*' -or $_.Subject -eq 'CN=driver1998 Test Signing' } |
      ForEach-Object { Write-Host "Removing cert $($_.Subject) from $store"; Remove-Item $_.PSPath }
  }
}

function Install-CiDriver {
  if (-not (Test-Admin)) { throw 'Run this from an elevated PowerShell.' }
  Write-Host 'WARNING: the stock driver froze this Pi (DPC_WATCHDOG 0x133). The CI build has a storm guard'
  Write-Host '         that should bugcheck (0x5D0C0001) and reboot instead. Be physically near the Pi.'
  if (-not $Yes) { if ((Read-Host 'Type YES to continue') -ne 'YES') { Write-Host 'Aborted.'; return } }

  $dir = Join-Path $env:TEMP 'rpiwin-ci'
  Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory $dir | Out-Null
  $url = "https://github.com/$Repo/releases/download/$Tag/bcm2836sdhc-arm64.zip"
  Write-Host "Downloading $url"
  Invoke-WebRequest -UseBasicParsing $url -OutFile "$dir\pkg.zip"
  Expand-Archive "$dir\pkg.zip" -DestinationPath "$dir\pkg" -Force

  $inf = Get-ChildItem "$dir\pkg" -Recurse -Filter bcm2836sdhc.inf | Select-Object -First 1
  $cer = Get-ChildItem "$dir\pkg" -Recurse -Filter *.cer | Select-Object -First 1
  if (-not $inf -or -not $cer) { throw 'package is missing bcm2836sdhc.inf or the .cer' }

  Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
  Checkpoint-Computer -Description 'pre-ci-sdhc' -RestorePointType MODIFY_SETTINGS -ErrorAction SilentlyContinue

  Remove-SdhcPackages
  Remove-TestCerts
  $c = Import-Certificate $cer.FullName -CertStoreLocation Cert:\LocalMachine\Root
  Import-Certificate $cer.FullName -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
  Write-Host "Trusted test cert: $($c.Subject)"

  pnputil /add-driver $inf.FullName /install | Out-Host
  Start-Sleep -Seconds 15
  Show-Status
  Write-Host ''
  Write-Host 'If the Pi rebooted/bugchecked: run  .\pi-test.ps1 -Action Bugcheck  and send the output.'
}

function Read-Bugcheck {
  $e = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'} -MaxEvents 3 -ErrorAction SilentlyContinue
  if (-not $e) { Write-Host 'No bugcheck events found.'; return }
  foreach ($x in $e) {
    $m = $x.Message
    $x.TimeCreated
    ($m -split "`n" | Select-Object -First 2) -join ' '
    if ($m -match '0x([0-9a-fA-F]{8})\s*\(0x([0-9a-fA-F]+),\s*0x([0-9a-fA-F]+),\s*0x([0-9a-fA-F]+),\s*0x([0-9a-fA-F]+)\)') {
      $code = [Convert]::ToUInt32($Matches[1],16)
      $p = 2..5 | ForEach-Object { [Convert]::ToUInt64($Matches[$_],16) }
      if ($code -eq 0x5D0C0001) {
        $bits = @{0x1='CMD_COMPLETE';0x2='XFER_COMPLETE';0x4='BLOCK_GAP';0x8='DMA';0x10='BUF_WRITE_RDY';0x20='BUF_READ_RDY';
                  0x40='CARD_INSERT';0x80='CARD_REMOVE';0x100='CARD_INTERRUPT(SDIO)';0x200='INT_A';0x400='INT_B';0x800='INT_C';
                  0x1000='RETUNE';0x4000='BOOT_ACK';0x8000='ERROR_SUMMARY'}
        $lo = $p[0] -band 0xFFFF; $hi = ($p[0] -shr 16) -band 0xFFFF
        Write-Host ('STORM GUARD TRIPPED  status={0:X8} status_enable={1:X8} signal_enable={2:X8} present_state={3:X8}' -f $p[0],$p[1],$p[2],$p[3])
        $set = $bits.Keys | Where-Object { $lo -band $_ } | Sort-Object | ForEach-Object { $bits[$_] }
        Write-Host ('normal bits set: ' + ($set -join ', '))
        Write-Host ('error bits: 0x{0:X4}' -f $hi)
        Write-Host ('present_state: card_inserted={0} dat_lines={1:X}' -f [bool]($p[3] -band 0x10000), (($p[3] -shr 20) -band 0xF))
      }
    }
    '---'
  }
}

switch ($Action) {
  'Install'  { Install-CiDriver }
  'Status'   { Show-Status }
  'Bugcheck' { Read-Bugcheck }
  'Cleanup'  {
    if (-not (Test-Admin)) { throw 'Run this from an elevated PowerShell.' }
    Remove-SdhcPackages; Remove-TestCerts; Show-Status
  }
}
