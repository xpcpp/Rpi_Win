# Pi agent

Lets Claude drive the Pi through GitHub (no inbound ports, no arbitrary shell).

* `agent.ps1` - scheduled task (SYSTEM, every minute + at boot). Reads `agent/commands/*.json`, runs allow-listed
  actions, posts the output as a comment on the "agent log" issue, posts a BOOT REPORT after every boot and disables
  the `sdioprobe` service if a bugcheck happened within 15 minutes of boot (crash-loop safety).
* `bootstrap.ps1` - one-time installer (needs a *fine-grained* token: this repo only, Issues read/write, Contents read).

Command file example (`agent/commands/0001-diag.json`):
```json
{ "action": "install", "only": "sdiofn" }
```
Allowed actions: `ping status info probe diag bugcheck rearm install cleanup disable-probe enable-probe reboot`.
Anyone who can push to this repo can run these actions on the Pi: keep 2FA on the GitHub account.
