# RIAN Commander V2 — macOS first-device pilot (Apple Silicon)

**Pilot target:** `Oui-MacStudio.local` (macOS 26.7.3, arm64).
**Status:** macOS source/CI work; real Mac install, enrollment and real-device E2E are NOT complete.
**Do not use DESKTOP-EEMFO3L for this pilot.**

## Boundaries

- Use the existing V2 staging API. The currently deployed synthetic A/B devices are
  not real Macs and must not be represented as one.
- Do not change the production Relay, Owner Gateway, D23, A100, Tailscale, firewall,
  working mail or any existing Mac application. No actual mail or IMAP data.
- Do not put a device token, token hash used with the real Mac, approver password,
  mailbox identity, or real messages into GitHub/CI/logs/chat.
- Enroll a **separate, Mac-only staging owner/device** with securely provisioned
  credentials and a separately approved device binding before real-agent execution.
- The first real Mac jobs must use `diag.wait` only, no mail job kinds.
- All commands below run **on the Mac under the owner account** using its normal
  terminal/Claude Code, not on a Windows PC. No administrator access is required.

## Requirements

- Python 3.10+ running on macOS under the owner account.
- macOS GUI session with an available `gui/$UID` launchd domain.
- The reviewed three Python files next to `install-v2-agent-macos.py`.
- Owner-prepared `agent.json` referencing a device token in a private local
  file owned by the current user with mode `0600`.
- The staging server has an owner principal and agent principal bound to the
  Mac's distinct device ID; this is **not provisioned yet**.

### Agent configuration shape (illustrative only; no secret values)

```json
{
  "relay_url": "https://<MAC-STAGING-ENDPOINT>",
  "device_id": "Oui-MacStudio.local",
  "state_dir": "/Users/o/Library/Application Support/RIAN-Commander-V2/state",
  "token_file": "/Users/o/Library/Application Support/RIAN-Commander-V2/secrets/device-token",
  "allowed_kinds": ["diag.wait"],
  "poll_seconds": 5
}
```

The token file itself must be owner-owned, mode `0600`, and contain a separately
provisioned, Mac-only credential. The installer never logs or copies its contents.
Do not paste any real secret into a chat or repository.

## Safe local sequence

From `rian-commander/eemf-operator` on the Mac:

1. `python3 install-v2-agent-macos.py status` — **read-only**, no files written.
2. Verify macOS, Python 3.10+, code hash, Mac-only staging enrollment and
   approval for the exact test scope. Keep `mail.*` excluded.
3. `python3 install-v2-agent-macos.py prepare --config /secure/path/to/agent.json`
   — writes a user-private agent copy and a **prepared plist outside
   `~/Library/LaunchAgents`**. **Does not activate** at this step or next login.
4. Inspect the prepared plist at
   `~/Library/Application Support/RIAN-Commander-V2/prepared-agent.plist`;
   run `plutil -lint` and the prepared agent's `status` command.
5. Only with specific owner approval to start the Mac V2 agent:
   `python3 install-v2-agent-macos.py install --config /secure/path/to/agent.json`.
   This installs a *per-user* `launchd` service and starts it. No admin privileges,
   firewall changes or inbound listener.
6. Start **one approved** `diag.wait` job (40 seconds) through staging. Verify
   immediate job ID, scoped browser approval, progress, result and idempotency.
7. Test supervisor restart and macOS login automatic restart. During a running
   job, preserve the runner and verify the same job ID result is collected once.
8. Remove the launchd service only after the job is terminal:
   `python3 install-v2-agent-macos.py uninstall`.
   This leaves the local token, journal, logs and config intact for audit/recovery.

## Go/no-go evidence

- macOS (arm64) actual host identity; `python3 --version` and launchd domain.
- Agent host registration restricted to this Mac; no EEMFO3L enrollment.
- `diag.wait` 40s with timestamp, one execution, result retrieved by `job_id`.
- Agent restart and macOS login reboot test; no duplicate dispatch.
- Client A/B tenant isolation and approval expiry/revocation remain intact.
- No mail access; no modifications to unrelated processes or services.

**GitHub CI macOS runners are useful but do not count as passing a real
Apple Silicon Mac Studio/launchd integration test.** Also, the existing V2
OAuth bridge is code-only until a separately authorized gateway connection.
