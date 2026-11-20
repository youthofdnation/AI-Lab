# RIAN Commander — pre-release usability and safety gates

Status: **Internal E2E, NOT ready for third-party/public beta**
Reviewed: 2026-11-19 KST
Scope: **RIAN Commander only.** This is not a request to change a project, Tailscale policy, firewall, Windows service, or training job.

## Verified today

| Capability | Evidence | Status |
|---|---|---|
| Fleet online inventory | 4 registered agents reported online | Read-only PASS; not proof of mutual network reachability |
| Owner gateway | Railway production, 5/5 services healthy | PASS, single environment |
| Owner-password scope | EEMFO3L exact Git clone, fetch, detached worktree and status/diff under one consent | Actual single-PC E2E PASS |
| Device editing | Fixed calculator example, SHA-based pre-write check and readback | Isolated example E2E PASS; not generic multi-PC |
| Toolchain presence | Python/Git/Node discoverable; Bun absent from agent PATH + conventional per-user location | EEMFO3L read-only observation PASS |
| Bun tests on EEMFO3L | Agent rejected attempt before test stdout or process exit | BLOCKED; missing executable likely, not proven globally |
| Cross-device direct port | No signed TCP/TLS probe available in fleet API | NOT VERIFIED |
| Multi-tenant permissions | One owner and globally fixed fleet/root exist | NOT IMPLEMENTED |
| Network preflight module | connection-preflight.ts + new fleet read-only MCP tool; 91 GitHub tests PASS | SOURCE COMPLETE, NOT DEPLOYED |

**Warning:** A read-only relay heartbeat or a reported status must never be described as verified TCP, TLS, or application readiness.

## P0 — gates before inviting external users

1. **Tenant isolation:** Scope every device, repository, approved operation, job, artifact and audit entry to an authenticated organization/tenant. No global admin token exposed across customers, no enumeration of another tenant's devices. Test negative cross-tenant access.
2. **Production-to-source security parity:** The deployed relay code differs from the reviewed GitHub `relay.ts` in *two EEM privilege enforcement lines* (`queue` and `runTool`). Before deployment, reconcile with a tested migration plan. The reviewed branch enforces owner proof for any privileged EEM operation and denies cross-device privileged operations; this may affect current admin workflows.
3. **Capability/connection preflight:** Check device online state, agent version and permission scope; independently collect source→destination listener, policy, TCP, TLS and authentication evidence. Only use verified remote results to mark EXECUTION_READY. The new read-only analyzer explicitly returns UNKNOWN or REPORTED_* for unverified data.
4. **Default connection transport:** Prefer agents' **outbound HTTPS relay** for command results and signed artifact transfer. Avoid requiring ordinary users to configure their own Tailscale ACLs or inbound Windows ports. Direct peer/Tailscale connections should be optional, with its limitations clearly displayed.
5. **Artifact exchange:** Implement resumable chunked upload/download through a trusted broker: per-tenant ownership, preauthorized source/destination, content hash and size limits, expiry, idempotency, replay controls and destination confirmation. A cloud relay existing for command polling is **not** equivalent to a verified artifact-transfer channel.
6. **Owner/administrator approvals:** For nonread-only changes, show exact device, repo/paths, executable/port, duration, maximum calls and rollback. Temporary Tailscale grants require a *separate* network-administrator approval. Never silently alter tailnet policies, host firewall rules, ports, or deploy settings.
7. **Recovery and audit:** Persist job queue, approval events (without secrets), checksums, checkpoints and retries across service restarts; support cancellation, timeout classification and recovery without repeated manual ZIP/copy/PIN. Ensure tasks cannot execute after expiry or revocation.
8. **Installer/dependency experience:** Signed, updateable cross-platform agent package, capability reporting, noninteractive safe toolchain doctor and bounded, explicit approval for any software install. Detect unavailable Bun before requesting Bun tests.
9. **Safe tenancy release:** Two independent test tenant accounts, each with multiple agents. Prove deny-by-default tenant access, roles, secrets, revocation, signed artifacts, no public listener, and operational monitoring/quotas.

## Proposed preflight UX (read-only MVP now in source)

A preflight request provides **two registered devices and a port/protocol**. The relay reads device heartbeats and optionally accepts clearly labelled, **unverified operator reports** for identity, listener, policy, transport, TLS and authentication.

The result is one of the following, with a next diagnostic step:
- Offline source/destination
- Identity or listener reported failing
- Network policy reported denying (not independently established)
- TCP timeout (ambiguous: route, firewall, policy, listener)
- TLS/auth failure reported separately
- Missing evidence
- All checks reported passing **but still not independently verified**

For a reported missing policy grant, output a **non-executable approval intent** with source, destination, protocol, port and review/rollback requirements. This does not change Tailscale policy or open a port.

The legacy relay **does not** collect actual TCP/TLS checks from agents yet. Do not change a report to VERIFIED until a new authenticated, signed, endpoint-level read-only probe is implemented and tested.

## D23-class reproduction acceptance scenarios (product tests, not access to Salpion)

| Scenario | Desired user-visible outcome |
|---|---|
| Both devices online but one inter-device TCP port blocked | "Devices online; service connectivity not verified" and exact next probe |
| Authenticated policy report says src→dst:tcp port denied | Approval request restricted to named nodes/port, separate admin consent; never auto-write policy |
| TCP passes but TLS fails | Identify TLS separately, no ACL recommendation |
| TLS passes but auth fails | Identify authentication separately, no firewall recommendation |
| Probe is missing or stale | No green READY claim; show evidence gap and recheck |
| Signed transfer interrupted | Resume verified chunks without requesting manual ZIP repetition |
| Service or gateway restart | Recover task state safely; no duplicate execution |
| Grant expires/revoked during job | Stop and report; remove only temporaries introduced by this session |
| Two unrelated tenants | No device, artifact, token, approval or log overlap |

## Definition of public beta readiness

No customer onboarding until all P0 gates are verified in production-like staging with **two independent tenant accounts** and a tested recovery/rollback path. Security review and documented data retention/permission controls are required. Passing Bun/GitHub unit tests alone is not sufficient.

## Current next release step

The new `connection-preflight.ts` and `rian_fleet_connectivity_preflight` MCP method have passed CI **in GitHub source**, but the Relay production source currently differs from GitHub's hardened implementation. **Do not copy over the entire relay and deploy without reviewing the impact on existing permissions.** After reconciling the drift, build a single-file Relay artifact, stage just the Relay Function change, get explicit deployment approval and test from the connected fleet account. Neither Tailscale nor host firewalls are touched by this module.

## 2026-11-21: EEMFO3L mail command regression — P0 before beta

An owner-approved local Outlook/ECOUNT bridge task was reported as
`RIAN_RELAY_AGENT_REJECTED_UNCLASSIFIED`. This **does not prove** the local
agent refused it. The deployed legacy Relay's synchronous `runTool` polls
112 × 250 ms (about 28 seconds), then raises `Job pending <UUID>`. The owner
gateway previously categorized that relay error as an unspecified agent
rejection. Jobs may later complete or expire without an owner-scoped result
lookup. **Never blindly retry sync**: re-running a task of unknown status
can duplicate work or local cache changes.

The deployed Outlook trusted profile permits **doctor / metadata search
only**. Mail `sync` and message `read` are explicitly excluded. Generic
command approval does not imply agent execution policy permits those
operations. The owner should not be routinely asked to open PowerShell to
complete the product workflow.

**Changes in PR #2, source only:** safer relay error taxonomy distinguishes
pending/unconfirmed, expired/unconfirmed, policy refusal, execution disabled,
missing executable, transport, workdir, timeout and process exit. Approval
failure UI displays bounded guidance with no raw sensitive error text.
Source-only `outlook-ops-scope.mjs` validates exact, bounded operations:
doctor/search (metadata), single message ID read (one-time specific owner
approval), and local-cache sync (1–14 days; max 1,000 messages, separate
owner approval). It **does not execute** any operation or expand permissions.
No changed gateway / mail permissions have been deployed.

### Acceptance criteria for actual user-ready mail functions

1. A single owner-approved EEMFO3L sync runs via the **durable asynchronous**
   job queue; use a scoped device identity and stable job ID. Show queued,
   running, completed, failed, expired, canceled or unknown (do not report
   a pending job as an agent rejection). Persist status and redacted reason.
2. The job runs without browser PIN, ZIP copying or repeated PowerShell
   once authorized; restart/reconnect must never duplicate unconfirmed sync.
3. Reading a selected email is separately approved for **exactly one message
   ID**. Limit output/pagination, prevent cross-account reads, don't log mail
   bodies or credentials, and respect organization retention controls.
4. Explicitly distinguish missing executable, local agent command policy,
   missing mail credentials, workdir mismatch, transport failure, and
   job timeouts before suggesting any environment changes.
5. An approval grants only an exact device, fixed script hash, bounded
   operation, allowed arguments, valid duration, and maximum calls. No
   general shell, send, delete, or mailbox mutation rights.
6. Run independent mock, Windows EEMFO3L (owner-approved), Relay restart,
   revoked token, oversize output and two-tenant access denial tests.
7. Do not enable user-facing mail features until the bridge's documented CLI
   and employer's authorized mailbox/data-handling scope are verified.

**Release gate:** the error classification tests and source-only command plan
are not a completed email connector. Product release is still blocked.
