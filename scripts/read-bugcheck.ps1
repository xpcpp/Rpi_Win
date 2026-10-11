<# Decode the last bugcheck. For the storm-guard patch (0x5D0C0001) the four parameters are
   raw Arasan SDHCI registers: STATUS(0x30), STATUS_ENABLE(0x34), SIGNAL_ENABLE(0x38), PRESENT_STATE(0x24).
   Send the output of this script back. #>
$e = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'} -MaxEvents 3 -ErrorAction SilentlyContinue
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
      Write-Host ("STORM GUARD TRIPPED  status={0:X8} status_enable={1:X8} signal_enable={2:X8} present_state={3:X8}" -f $p[0],$p[1],$p[2],$p[3])
      $set = $bits.Keys | Where-Object { $lo -band $_ } | Sort-Object | ForEach-Object { $bits[$_] }
      Write-Host ("normal bits set: " + ($set -join ', '))
      Write-Host ("error bits (0x{0:X4}): {1}" -f $hi, $(if ($hi) {'see SDHCI error status'} else {'none'}))
      Write-Host ("present_state: card_inserted={0} dat_lines={1:X}" -f [bool]($p[3] -band 0x10000), (($p[3] -shr 20) -band 0xF))
    }
  }
  '---'
}
