# RIAN Commander — tenant isolation / artifact exchange staging slice

Date: 2026-11-20. Scope: PR #2 branch only. **NOT deployed or ready for public beta.**

## Why this exists

The legacy Relay has globally registered device keys and administrative operations.
An online fleet does not establish any customer separation. The deployed Relay
also differs from the hardened PR source: production `queue()` accepts a
privileged action without the same EEMF owner-proof requirement enforced by the
PR branch, and production `runTool()` guards the EEMF target only. Do not
overwrite the production Function with the PR branch or remove existing agents.

## New source files

- `tenant-artifact-core.mjs`: separate per-tenant device directory, bearer-token
  hash authentication, owner versus agent roles, bound approval proof, bounded
  resumable SHA-256 chunk transport, expiration and cancellation.
- `tenant-artifact-http.mjs`: **unmounted** HTTP handler for staging only.
  No caller-provided tenant override, no general shell/file path access and no
  global administrator bypass; cross-tenant denials are 404.
- `tenant-artifact-core.test.mjs` and `tenant-artifact-http.test.mjs`: two
  independently authenticated tenants (each with two devices), negative access,
  nonces/replay, chunk resume, integrity and acknowledgement.
- `.github/workflows/rian-tenant-artifacts.yml`: Node 22 source/HTTP tests and
  a guard preventing the unreviewed handler from being mounted into legacy Relay.

### Staging API contract, not enabled

| Action | Authenticated role | Staging route |
| --- | --- | --- |
| List own devices | owner | `GET /v2/tenant/devices` |
| Begin approved transfer | owner with separately signed exact grant | `POST /v2/transfers` |
| Upload/retry chunk | source device agent | `PUT /v2/transfers/{id}/chunks/{index}` |
| Verify whole-file digest | source device agent | `POST /v2/transfers/{id}/finalize` |
| Fetch verified chunk | target device agent | `GET /v2/transfers/{id}/chunks/{index}` |
| Confirm destination digest | target device agent | `POST /v2/transfers/{id}/ack` |
| Cancel pending transfer | owner | `POST /v2/transfers/{id}/cancel` |

Transfer is by approved exact source/target IDs and a harmless artifact
display-name, **not** an arbitrary local filesystem path. The receiving agent
must later implement an explicit, owner-approved inbox target and atomic
write+readback before acknowledging. The test signer simulates a pre-approved
owner consent; it does not itself authenticate the owner in a browser.

Current deliberately small limits: 64 KiB per chunk, 8 MiB per transfer, 1h
transfer expiry and 5m maximum approval-grant validity. Test-only process
memory loses all chunks on restart. A process cannot be considered a durable
or production-ready broker. The current prototype does **not** encrypt content
at rest or implement endpoint-to-endpoint encryption.

## Deployment gates (all mandatory)

1. Create a separately deployed staging service and store, never overwrite the
   five production Functions as a shortcut. Audit existing production-to-PR
   privilege drift first, including all legacy admin and EEMF approval flows.
2. Use durable per-tenant transactional metadata, a replay-proof store, an
   encrypted-at-rest private object bucket, per-tenant quota/rate limits, and
   cleanup after revocation or expiry. Prove restart and concurrent upload
   behavior on 2+ replicas.
3. Keep the approval signing secret inside a privileged owner-approved browser
   handler. Never export it to agents, public clients, ChatGPT or logs. Bind
   consent to source, destination, bytes, SHA-256, principal, expiration and
   audit event. Support explicit revocation.
4. Build agent opt-in for the **outbound HTTPS** channel. Give each agent
   short-lived device-bound credentials, a reviewed approved inbox, atomic
   destination checksum verification, and resumable status. Never instruct
   customers to edit Tailscale ACLs/inbound host ports for standard transfers.
5. Run actual Windows EEMFO3L ↔ 1Q transfers with separately approved
   permissions; keep 1Q read-only until a specific approved transfer profile
   is enabled. Test timeouts, cancellation, token revocation, device restart
   and destination disk exhaustion. Do not access SALPION or D23 files in
   this product-test phase.
6. Test at least **two unrelated owner accounts** in an isolated staging
   deployment, including attempts to enumerate/invoke another customer's
   device/job/chunk/approval. Validate audit retention and incident rollback.
7. Deploy only after security review and explicit separate production approval.

**Verified only in local Node unit/HTTP tests:** 26 passing cases at
development time. GitHub Actions and real-machine E2E are separate checks;
do not claim they passed until their own evidence is available.

## Tenant-scoped command queue (also source-only)

- `tenant-job-policy.mjs` adds a second staging-only boundary for device jobs:
  owner-initiated read-only queueing, exact action/argument SHA-256 approval
  for write/execute, per-tenant+device polling and result retrieval.
- Agents cannot impersonate owners or poll/complete a different tenant's job;
  unknown keys, sensitive paths and shell argument control characters are
  rejected before any agent receives work.
- The 120-second in-flight lease is **fail closed**: its expiry becomes
  `UNKNOWN_DO_NOT_RETRY`, not a duplicate command execution.
- A cancellation requested after a command was dispatched is reported as
  `CANCEL_REQUESTED`; this is **not evidence that the local process stopped**.
- The queue and approval nonce set are process-local test mechanisms.
  Production needs atomic durable leases, client acknowledgment, revocation,
  audit metadata, rate limits and crash/restart drills.

The production Relay still uses its earlier global device/admin data model.
Do not claim tenant isolation is deployed until migrated and tested with two
separate accounts. No 1Q permissions were changed and no D23 job was started.

## 2026-11-20: durable staging implementation and live volume verification

Added separate, **not production-connected** modules:

- staging-sqlite.mjs: Node 22.16+ SQLite WAL, FULL synchronous commits,
  encrypted AES-256-GCM transfer chunks and job args/results, durable approval
  nonces and idempotency, tenant-scoped audit metadata, and a key sentinel.
- durable-tenant-artifacts.mjs: 64 KiB resumable chunks, 8 MiB max per transfer,
  32 MiB active quota per tenant, atomic database operations, encrypted chunks,
  whole-file digest, destination acknowledgment and cancellation.
- durable-tenant-jobs.mjs: exact-scoped signed approval, tenant/device polling,
  encrypted output, request-key deduplication and fail-closed restart recovery.
  A dispatched job interrupted by restart becomes UNKNOWN_DO_NOT_RETRY, **not**
  a replayable job.
- staging-entry.mjs + Dockerfile.staging: isolated service with /health and a
  disabled-by-default /v2 authenticated API. It requires a separate staging
  tenant directory, separate browser approval signer, explicit env opt-in and
  an encrypted persistent /data volume.
- tenant-artifact-agent.py: opt-in Python standard-library client over outbound
  HTTPS only, file source-root and destination-inbox confinement, SHA-256,
  chunk retry, no-overwrite atomic hard-link commit and safe acknowledgment.
  No cross-PC inbound port or Tailscale policy change is needed by its design.

**Railway staging evidence:** A separate private Railway project named
rian-commander-tenant-staging was created, with one isolated service and an
attached 512 MiB persistent volume. A known CI-tested source SHA was pinned
for its initial deployment; healthcheck and deploy succeeded. A separate
redeploy succeeded and the encrypted volume boot counter advanced **1 to 2**.
No public service domain was created. The v2 file/command API remains OFF.
The existing five Railway production functions and four-PC fleet configuration
were not changed.

**CI evidence:** the 37 Node policy/restart tests passed, the Docker-based
volume replacement test passed, and the 10 synthetic Python agent tests passed
on Linux and Windows in the checked workflow. These are tests with *fake
tenant accounts and fixture files*, NOT live EEM↔1Q file exchange.

### Remaining hard release blockers

1. A *separate* browser-based exact-scope owner consent issuer; the development
   approval signers must never be callable through an agent or public API.
2. Two real independently authenticated owner accounts, tenant provisioning,
   secret rotation, revocation, audit export/retention, quota alarms, and negative
   E2E penetration tests in staging.
3. Agent enrollment and opt-in for source and destination PC, with verified
   device identity, per-device credential provisioning and an approved local
   source path and destination inbox. Current Python client is a manually
   configured prototype, not a signed Windows/macOS installer.
4. Durable transactional job cancellation/ack of process stop and detailed
   retry reconciliation. UNKNOWN_DO_NOT_RETRY preserves safety but requires a
   human or idempotent agent to reconcile outcomes.
5. SQLite-backed staging uses **one replica only** and Node's experimental
   sqlite API. Multi-replica commercial production requires external
   transactional storage, independent encrypted object storage, backup and
   restoration tests, and key rotation.
6. Actual approved Windows EEMFO3L and 1Q transfer, test of loss/reconnect,
   and explicit 1Q write opt-in. Leave the read-only 1Q flags unchanged until
   its owner explicitly consents to a bounded transfer.
7. Relay production/source privilege drift: do not copy source over production
   or merge PR #2 wholesale without reviewed migration and rollback.
8. Verify source/target file paths and platform-specific filesystem race
   protections; do not access SALPION D23 training data as a product fixture.

Customer release remains **BLOCKED**. Staging deploy is not a public beta.
