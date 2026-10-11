<# Remove every bcm2836sdhc driver package and the test certs (CI one + driver1998). Run elevated. #>
$ErrorActionPreference = 'Continue'
$cur = $null
pnputil /enum-drivers | ForEach-Object {
  if ($_ -match 'Published Name:\s+(oem\d+\.inf)') { $cur = $Matches[1] }
  if ($_ -match 'Original Name:\s+bcm2836sdhc\.inf' -and $cur) {
    Write-Host "Removing $cur"; pnputil /delete-driver $cur /uninstall /force
  }
}
foreach ($store in 'Root','TrustedPublisher') {
  Get-ChildItem Cert:\LocalMachine\$store |
    Where-Object { $_.Subject -like 'CN=Rpi_Win CI test signing*' -or $_.Subject -eq 'CN=driver1998 Test Signing' } |
    ForEach-Object { Write-Host "Removing cert $($_.Subject) from $store"; Remove-Item $_.PSPath }
}
Get-PnpDevice -InstanceId 'ACPI\BCM2847\0' | Select Status,Class,FriendlyName
