# Rpi_Win

Bringing up onboard hardware (WiFi first, GPU later) on **Raspberry Pi 400 / Pi 4, Windows 11 ARM64** (UEFI: pftf/RPi4, test-signing ON).

Everything is built in GitHub Actions; the Pi is only used for testing.

## Layout
| Path | What |
|---|---|
| `.github/workflows/build-sdhc.yml` | Builds patched `bcm2836sdhc` (Arasan SDHCI, `ACPI\BCM2847`, the WiFi SDIO host) for ARM64, signs with a throw-away cert |
| `patches/` | Patches applied on top of `raspberrypi/windows-drivers` (pinned commit in the workflow) |
| `scripts/` | PowerShell for the Pi: install, cleanup, decode bugcheck |
| `docs/NOTES.md` | Hardware facts collected from Pi OS and from the crash dump |

## Test loop
1. Actions -> `build-bcm2836sdhc` -> *Run workflow*. Download artifact `bcm2836sdhc-arm64-runN`.
2. On the Pi (elevated PowerShell, **only when you can reach the Pi physically**):
   `.\install-ci-driver.ps1 -Dir <extracted folder>`
3. After it reboots/bugchecks: `.\read-bugcheck.ps1` and send the output back.
4. `.\cleanup.ps1` removes the driver and the test certs.

## Status
- Stock worproject `bcm2836sdhc` bound to `BCM2847` -> `DPC_WATCHDOG_VIOLATION (0x133)`, whole system frozen.
- Patch 0001 adds an interrupt-storm guard that masks the controller and bugchecks with
  the raw SDHCI registers as parameters, so the cause can be read after reboot.
- Workflow is an untested first draft: if a step fails, send the failing step's log.
