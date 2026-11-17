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


## Additional security hardening (2026-11-16)

Relay and EEMFO3L OAuth gateway now require a **second, short-lived HMAC approval proof** for any write or command, bound to the exact operation, arguments, nonce and expiration. The original relay admin MCP code path rejects EEMFO3L writes and command execution without an internal verified approval flag; it cannot silently bypass the browser approval page. The gateway creates that proof only after the owner signs into its independent per-action approval page. Replay nonces are cached temporarily on the relay.

Both services were deployed via the existing Railway project and returned SUCCESS; Windows and Bun checks passed. A subsequent attempt to invoke privileged negative tests via an automated Railway test harness was blocked by the execution tool's safety checks. Therefore **live post-hardening command denial is not yet demonstrated**, and EEMFO3L local command/write opt-in must be treated as pending explicit owner action and a final E2E check.

Current local EEMFO3L agent status: `can_exec=false`, `can_write=false`; read-only status and Documents/RIAN-Proton-Tools directory listing verified. Other PCs' permissions are unchanged.

## Operator next step

On DESKTOP-EEMFO3L, review the pinned `enable-eemf-owner.ps1` source and run it without arguments to see permission status. Run `-Enable` locally only after agreeing to per-action remote command/file approvals. `-Disable` reverts the device flags.

To use in a regular ChatGPT web conversation, the user must separately create and authorize a custom MCP plugin/app with the endpoint `https://rian-eemf-owner-gateway-production.up.railway.app/mcp` if account/workspace policies provide that option. A Codex-only MCP connection does not make the tool appear in another ChatGPT chat. Official support for full MCP write actions may depend on Business/Enterprise/Edu entitlements.


## 2026-11-17 — Bounded read-only trusted sessions (deployed)

**Status:** Code and unit tests complete, deployed to the existing `rian-eemf-owner-gateway` service on Railway; deployment SUCCESS. **Browser approval and authenticated ChatGPT tool calls for the NEW session tools have not yet been tested E2E**, because the existing conversation's plugin tool schema still exposes only the previous six tools.

### Four new MCP tools

- `rian_eemf_request_trusted_session`: returns a browser approval URL and a pending session ID; does not execute a command.
- `rian_eemf_trusted_session_status`: reports state, expiration, and remaining call allowance, bound to the requesting OAuth client.
- `rian_eemf_run_trusted_command`: accepts a session ID and ONLY a validated Proton local status/subject-search command within the approved workspace.
- `rian_eemf_revoke_trusted_session`: revokes the session immediately without needing the original password.

The owner approves **once** in the independent HTTPS browser page by entering the existing owner password. Activation permits up to **30 minutes or 60 command invocations**, whichever comes first. The permission is fixed to DESKTOP-EEMFO3L and the exact Proton local read-only profile. Each command is protected by a separate, one-use HMAC relay approval proof. The trusted script's SHA-256 is compared with the approval-time version before each invocation. Commands are serialized; no extra calls execute after expiry, exhaustion, or revocation. Requester OAuth client IDs must match. Logs contain session ID digests and lifecycle metadata, not passwords or mail query strings.

**Allowed** in `Documents/RIAN-Proton-Tools`: `python proton_mail_query.py status` and `python proton_mail_query.py search TERM [--limit 1..20]`.

**NOT allowed:** Proton body reads, `--full-text`, `--all`, Proton ingest/sync, Outlook sync, file writes, arbitrary PowerShell/Python, other computers, or unrestricted terminal execution. These still require separate approval or a new reviewed profile.

### Limitations and next step

- Sessions are in the gateway's process memory; restarting/redeploying it immediately invalidates all active grants (fail closed).
- The central relay privileged queue guard in the PR remains **unmerged and not deployed**; do not describe public multi-user isolation as complete.
- CI validates the command allowlist, OAuth client isolation, real session lifecycle transitions, expiry, revocation, max-call enforcement, existing per-command approval and PowerShell script compatibility.
- To verify E2E, refresh/reconnect the personal `rian_eemf_owner` ChatGPT MCP connection so the new four tools are discovered; request a session, approve once in the browser, execute two allowed commands without additional password prompts, then revoke and verify refusal.
- For Outlook's `outlook_bridge.py sync --days 180 --max-messages 3000`, the source reads IMAP and writes a local index but may exceed the current synchronous relay limit. Build an independently approved durable background job workflow before admitting it to a trusted profile. Confirm employer policy and data-retention requirements.

