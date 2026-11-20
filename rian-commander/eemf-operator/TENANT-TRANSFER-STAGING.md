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

**Verified only in local Node unit/HTTP tests:** 17 passing cases at initial
development time. GitHub Actions and real-machine E2E are separate checks;
do not claim they passed until their own evidence is available.
