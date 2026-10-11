<#
 Install the CI-built bcm2836sdhc driver on the Pi (Windows 11 ARM64, test mode ON).
 Run from an *elevated* PowerShell, inside the folder where you extracted the artifact.
 Takes a restore point first, trusts the CI test cert, installs the driver.
 !! The original package hung the Pi (DPC_WATCHDOG 0x133). Only run this when you can
 !! physically reach the Pi. The patched build should bugcheck (0x5D0C0001) instead of hanging.
#>
param([string]$Dir = '.')
$ErrorActionPreference = 'Stop'
$cer = Get-ChildItem $Dir -Filter *.cer | Select-Object -First 1
$inf = Join-Path $Dir 'bcm2836sdhc.inf'
if (-not $cer -or -not (Test-Path $inf)) { throw "need bcm2836sdhc.inf and the .cer in $Dir" }

Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
Checkpoint-Computer -Description "pre-ci-sdhc" -RestorePointType MODIFY_SETTINGS -ErrorAction SilentlyContinue

$c = Import-Certificate $cer.FullName -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate $cer.FullName -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
Write-Host "Trusted test cert: $($c.Subject)  $($c.Thumbprint)"

pnputil /add-driver $inf /install
Start-Sleep -Seconds 15
Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'ACPI\BCM2847*' -or $_.InstanceId -like 'SD\*' } |
  Select Status,Class,FriendlyName,InstanceId | Format-Table -Auto -Wrap
