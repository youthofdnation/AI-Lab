# RIAN Commander V2 — durable long-running jobs, ChatGPT MCP and work mail

Status (2026-11-21, DESKTOP-1QGT8D6): **source complete, unit + real-process E2E
verified on Windows; not deployed.** Railway staging deployment, installation on a
real PC and any real mailbox access each still need an explicit owner approval.
Built on branch `feature/rian-commander-v2-durable-jobs` from `2ea75d8`
(`feature/rian-eemf-owner-command-mcp`, PR #2), without changing PR #2 or any
production service.

## Why

The deployed legacy Relay waits synchronously 112 × 250 ms (≈ 28 s) and then
throws `Job pending <id>`; the gateway could not tell "still running" from
"rejected", jobs lived in memory, and a mail sync could not finish or be
recovered. V2 moves long work to the isolated staging service
(`rian-commander-tenant-staging`) with a durable SQLite volume.

## Architecture

```
ChatGPT ──OAuth──> Owner Gateway (gateway.ts)  ──rian_v2_* + owner token──> Staging service (/v2/mcp)
                                                                          │ SQLite (AES-GCM params/results)
Owner browser ── password ─────────────────────────────> /v2/approve/<job> │
PC agent (rian-v2-agent.py) ── outbound HTTPS poll ─> /v2/agent/claim | heartbeat | complete
           └─ detached runner ── rian_mail_index.py (read-only IMAP, local index)
```

| Module | Reuses | Role |
|---|---|---|
| `long-job-kinds.mjs` | `outlook-ops-scope.mjs` (`planOutlookOperation`) | Job kinds + bounds. Server sends only `(kind, params)` — never argv, shell, cwd or paths |
| `durable-long-jobs.mjs` | `StagingSqlite`, `TenantDirectory` | Queue: approval, standing grants, lease tokens, heartbeats, recovery, dedup |
| `long-job-http.mjs` | — | `/v2/mcp` tools, agent API, password approval page (CSRF ticket, Origin check, rate limit) |
| `staging-server.mjs` / `staging-entry.mjs` | artifact broker/handler | One service; health-only unless explicitly enabled |
| `gateway.ts` (+~1 KB) | existing OAuth | Lists and forwards `rian_v2_*` after the access-token check |
| `rian-v2-agent.py` | `tenant-artifact-agent.py` `Client` (HTTPS-only, no redirects) | Supervisor + detached runner, journal, exactly-once per PC |
| `rian_mail_index.py` | — | Read-only IMAP (EXAMINE + BODY.PEEK), merge, backup, account binding |
| `install-v2-agent.ps1` | pattern of `enable-eemf-owner.ps1` | One-time per-user logon task; status-only by default |

## Job lifecycle

`AWAITING_APPROVAL` → (browser password) → `QUEUED` → (agent claim, secret lease) →
`RUNNING` ⇄ heartbeat/progress → `SUCCEEDED | FAILED | CANCELLED | TIMED_OUT | INTERRUPTED`.
Also `APPROVAL_CANCELLED`, `APPROVAL_EXPIRED` (15 min), `EXPIRED` (approved but not
claimed in 6 h), `UNKNOWN_DO_NOT_RETRY` (lease lost). Nothing is ever re-queued.

* **Long work**: job id returned immediately; runtime caps per kind (sync 60 min, diag 16 min).
* **Server restart**: RUNNING jobs stay RUNNING with a 180 s grace lease; only the
  lease-token holder can report, so the original run's result is still collected.
* **Agent restart**: the runner is a detached process; the restarted supervisor
  resumes from its journal. A dead runner without a result → `INTERRUPTED` (never re-run).
* **Late result**: an authentic result after `UNKNOWN_DO_NOT_RETRY` is accepted (24 h).
* **Duplicates**: request key idempotency, identical active spec returns the same
  job, one active job per lock group (one mail sync per PC), PC-side executed-id list.
* **Cancel**: pending approval, queued job, or running job (agent stops at a safe point).
* **Oversized result**: replaced once by `OUTPUT_TOO_LARGE` instead of retrying forever.
* **Approval brute force**: 5 failures per client and 10 per job (spoofed `X-Forwarded-For` cannot bypass).

## ChatGPT tools (via the existing OAuth gateway)

`rian_v2_devices`, `rian_v2_start_job`, `rian_v2_job_status` (`wait_seconds` ≤ 20),
`rian_v2_list_jobs`, `rian_v2_cancel_job`, `rian_v2_list_grants`, `rian_v2_revoke_grant`.
There is **no approve tool**; approval always needs the owner password in the browser.

## Work mail

* `mail.sync {days 1-14, maxMessages 1-1000}` — durable job only. Merges new mail,
  never removes existing entries (a 120-day index stays), backs up the previous
  index (last 10) and writes atomically. Different account → `ACCOUNT_MISMATCH`
  before any write. A legacy JSON index can seed the V2 index once (read-only).
* `mail.search {query, limit ≤ 20}` — subject/sender/date/message id only.
* `mail.read {messageId}` — exactly one message body (≤ 64 KB, shrunk to fit the relay request limit); **never pre-approvable**; the encrypted body result is purged from the server 1 h after the read.
* General fleet / owner file reads now deny `rian-mail-v2`, `rian-outlook-bridge`
  (fleet) and `.eml/.mbox/.msg/.pst/.ost` (relay, gateway, tenant policy).
* No send, delete, move, flag or append code path exists.

## Convenience without weakening approval

The approval page can add an **exact-scope standing grant**: same PC, same kind,
same canonical params, 1–1440 minutes, 1–50 extra runs, revocable from ChatGPT.
Repeated identical syncs then queue without a password. The agent runs as a
per-user logon task, so no PowerShell window is needed after the one-time install.

## Configuration (staging)

`RIAN_STAGE_JOBS_ENABLED=1`, `RIAN_STAGE_PUBLIC_URL`, `RIAN_STAGE_FORM_SECRET` (≥ 48 B),
`RIAN_STAGE_PRINCIPALS_JSON` / `RIAN_STAGE_DEVICES_JSON` (≥ 2 tenants, token SHA-256 only),
`RIAN_STAGE_APPROVERS_JSON` (scrypt salt/hash only; `hashApprovalPassword()`),
`RIAN_STAGE_ALLOW_DIAGNOSTICS=1` only for the synthetic `diag.wait` kind.
Gateway: `RIAN_V2_MCP_URL=https://<staging>/v2/mcp`, `RIAN_V2_OWNER_TOKEN`.
No secret value belongs in GitHub, chat or logs.

## Railway Function size

`compact-utf8.mjs` rewrites Bun's `\uXXXX` Hangul escapes (6 B) to UTF-8 (3 B)
and refuses to write unless the change is byte-for-byte reversible. The current
artifact shrinks 97,965 → 89,178 bytes, leaving room for the V2 bridge under the
98,295-byte limit.

## Verification on DESKTOP-1QGT8D6 (Windows 11, Node 24.11.1, Python 3.12.10)

| Suite | Result |
|---|---|
| `durable-long-jobs.test.mjs` | 14/14 |
| `long-job-http.test.mjs` | 7/7 |
| `rian_mail_index.test.py` | 14/14 |
| `rian-v2-agent.test.py` | 14/14 |
| Existing Node suites (incl. crosslang, now Windows-safe) | 44/44 |
| Existing Bun gateway/relay suites + `v2-bridge.test.ts` (Node shim locally; CI runs Bun) | 100/100 |
| `v2-process-e2e.test.mjs` real processes | PASS (≈ 52 s) |

E2E evidence (synthetic tenants/mailbox): job id returned in < 1 s, owner password
approval, 40 s job ran 41 s; staging service hard-killed and restarted mid-run
(`runningPreserved:1`); agent supervisor hard-killed and restarted (journal
recovered); `SUCCEEDED` with audit `AWAITING_APPROVAL > APPROVED > DISPATCHED >
LEASE_RESTART_GRACE > SUCCEEDED` (dispatched once). Duplicate and conflicting
requests deduplicated; tenant B got `NOT_FOUND` for A's job/PC. Mail: 240-entry
120-day legacy index kept + 14-day merge → 252, second sync via standing grant
without password (added 0, backup written), metadata search without bodies, one
selected body read, grant revoked → approval required again.

## Remaining gates (owner approval required)

1. Deploy to `rian-commander-tenant-staging` only (needs Railway access, volume, env).
2. Configure the gateway with the staging V2 URL; ChatGPT reconnect to discover tools.
3. Install the agent on a real PC (`install-v2-agent.ps1 -Install`) — not done.
4. Real mailbox: confirm employer policy, IMAP host/account, and the legacy
   `outlook_bridge.py` index format before seeding (EEMFO3L was not read).
5. Production Relay and PR #2 remain unchanged.
