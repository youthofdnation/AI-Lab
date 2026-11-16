# RIAN Commander — DESKTOP-EEMFO3L owner-operated MCP

## Verified state (2026-11-16)

The user's current Windows PC is **DESKTOP-EEMFO3L** and already has the existing RIAN Commander outbound HTTPS agent installed. This is the PC that holds the approved local Proton Mail tools under `Documents/RIAN-Proton-Tools`. No mailbox contents were accessed in this development.

A separate `rian-eemf-owner-gateway` Railway Function was deployed successfully at:
`https://rian-eemf-owner-gateway-production.up.railway.app/mcp`

The original `rian-commander-oauth-gateway` remains a four-PC, read-only fleet MCP, and the separate D23 services remain untouched.

## New security boundary

- Relay: `POST /mcp/eemf-owner`, with dedicated `RIAN_EEMF_GATEWAY_TOKEN`. An EEMF-only hard-coded device target denies other device requests.
- OAuth MCP gateway: `eemf:operate` scope, separate derived signing key, independent callback/resource and owner login.
- MCP actions: `rian_eemf_status`, `rian_eemf_list_directory`, `rian_eemf_read_file`, `rian_eemf_request_command`, `rian_eemf_request_write`, `rian_eemf_action_status`.
- Command/write MCP actions only **create an approval request**. An owner must view exact argv/file content and enter a password on a separate approval webpage to execute that one action. The gateway cannot approve itself through an MCP tool.
- All actions are scoped to EEMFO3L's existing allowed home directory; sensitive local paths are denied; no other machines' permissions are expanded.
- Script `enable-eemf-owner.ps1` only changes EEMFO3L's local `config.json` flags `can_exec` and `can_write` and restarts that same agent. Defaults to status-only with no changes. `-Enable` locally opts in; `-Disable` reverts.
- User action to register the new MCP endpoint in the intended ChatGPT surface is still required. Custom MCP surface, plan and workspace permissions may restrict ordinary ChatGPT usage.

## Live verification

- Gateway /health 200 ready true, owner manual approval required.
- OAuth authorization metadata 200, only `eemf:operate` + `offline_access`.
- Anonymous `/mcp` call 401; allowed loopback OAuth client registration 201; disallowed redirect 400.
- Restricted relay anonymous request 401.
- Restricted relay authenticated status returned EEMFO3L, `can_exec=false`, `can_write=false` as of this verification.
- Relay list `Documents/RIAN-Proton-Tools` succeeded; device override and attempted secret-file path denied.
- GitHub Actions checks passed on Windows (PowerShell opt-in syntax), Bun (gateway/relay compilation and security policy).
- Temporary Railway probe service removed. All five long-lived services deployed SUCCESS.

## Remaining gates

1. EEMFO3L owner runs `enable-eemf-owner.ps1 -Enable` locally. No privileged execution has occurred before this local opt-in.
2. User registers and OAuth-authorizes the new EEMF MCP, verifies tools/list.
3. Perform approved harmless read/status tool call followed by one separately approved harmless command; verify response and rollback.
4. Confirm that the intended ChatGPT conversation can select the custom plugin/app; Codex MCP connection does not automatically expose tools in an unrelated conversation.
5. Only then run the existing local Proton query script after confirming its usage and data freshness. Live Proton availability is not implied by the existence of local export files.

No access tokens, owner password, Proton content, or private key material belongs in GitHub, chat, or test logs.
