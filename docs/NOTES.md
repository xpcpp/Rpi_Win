# Hardware notes (Pi 400)

## From Raspberry Pi OS (native firmware DT, not UEFI/ACPI)
- Arasan SDHCI (`mmcnr`, WiFi): regs `0xfe300000` len 0x100; eMMC2 (SD card slot): `0xfe340000`.
- IRQ: GIC 158 (SPI 126), level, shared by mmc0 (eMMC2) and mmc1 (Arasan).
- Clocks: `emmc` 250 MHz (matches the hardcoded value in bcm2836sdhc), `emmc2` 100 MHz.
- WiFi chip on SDIO: vendor 0x02d0, device 0xa9a6, functions 1-3, 4-bit, SD high-speed (50 MHz requested, 41.67 MHz actual).
- Linux: BCM4345/9, firmware `brcm/brcmfmac43456-sdio`, fw version 7.84.17.1. Check `/lib/firmware/brcm` for 43456 .bin/.clm_blob/.txt.
- No pwrseq/reset GPIO in the DT: firmware powers the WiFi chip, so it is alive at Windows boot.
- GPIO 34-39 = ALT3 (SD1 CLK/CMD/DAT0-3).
- Linux dmesg: "mmc1: Controller never released inhibit bit(s)" at init (benign in Linux).
- Linux uses DMA on mmc1; the Windows miniport is PIO only.

## From ACPI source (edk2-platforms, Sdhc.asl / Emmc.asl)
- `BCM2847` (Arasan) and `BRCME88C` (eMMC2) both declare `Interrupt(Level, ActiveHigh, Shared)`.
- `BCM2847` has `_DSD sdhci-caps = 0x0120fa81` (controller CAPS read as 0).

## Crash dump (stock driver)
- `0x133` (DPC_WATCHDOG_VIOLATION), Arg1 = 1 (single DPC/ISR too long).
- `bcm2836sdhc.sys` loaded, `sdport.sys`/`sdbus.sys` active in the stack region; no code address of bcm2836sdhc itself in the triage dump.
- Source review: no unbounded loops in the driver; ISR returns TRUE whenever status != 0. Leading hypothesis: interrupt that is never cleared (SDIO card interrupt / error / card-detect) on a shared level IRQ.

## Windows device states seen
- Error Code 28 (no driver): `BCM2847`, `BCM2835`, `BCM2848`, `BCM2850`, `BCM2854` (GPU-side, no INF in the package), `PNP0C06`.
