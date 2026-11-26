# Repeated approval investigation and implementation status (2026-11-26 KST)

## Field update — 2026-11-26 19:43 KST

This section supersedes the earlier source-only status below. The owner used
Google identity bootstrap and a phone passkey to approve one 30-day Outlook
read-only policy for EEMFO3L and the exact account/OAuth connection. The six
mail tools are visible and callable from this ChatGPT connection. The EEMFO3L
V2 agent is online and ran actual jobs. No production or other-device grant was
changed.

- Latest PR head `b4edb56`: all 16 CI checks passed, including Windows, macOS,
  Linux process E2E, gateway, Docker image, staging volume and tenant isolation.
- The EEMFO3L mail staging service deployed validated commit `381e563` as
  Railway deployment `370f1077-ad98-4423-ade1-fd966a31c97d` (SUCCESS).
  The previous successful deployment `2107b62e-5f3c-4a59-a6d0-27b0f3d2f82c`
  remains the rollback reference. The later PR commit only bounds the local
  Bridge body parser output; the PC agent has not received that fix.
- The first 14-day sync ended `RUNNER_PERMISSIONERROR` at 5% with no automatic
  retry. One manually initiated retry succeeded: 100 fetched, six added, 116
  total, zero removed, local index backup created, mailbox unchanged. The
  exception was transient in this run; its underlying OS cause is not proven.
- Status, sync, paginated recent mail, multiple searches, sent comparison and
  selected body reads all queued and completed without another browser approval.
  The policy survived the Railway redeploy; a post-redeploy status, search and
  nonempty body read succeeded under the same grant. A 15-day sync was denied
  with `MAIL_SCOPE_DENIED` before execution.
- Some older messages have empty cached bodies despite appearing cached in
  current PC-agent results. The installed Bridge extracts only `text/plain`.
  PR #14 now provides an HTML-to-text fallback and reports zero-byte body files
  as uncached. These changes passed tests but cannot repair the local index
  until the EEMFO3L agent is updated through an authorized deployment path and
  resynced. Remote Desktop Commander for EEMFO3L is offline; the mail-only
  policy grants no code-write or shell permission. Do not bypass that scope.
- The live grant has not been revoked because doing so would remove the user's
  working read-only policy. Actual revocation, new-ChatGPT-session reuse,
  Railway volume backup/restore, Proton isolation and Level 1/2 fleet behavior
  remain unverified. Mail business review is partial while older bodies remain
  unavailable. **MAIL E2E and RELEASE remain BLOCKED.**

## Observed cause

The production `rian-eemf-owner-gateway` is a legacy Railway Function. Its deployed
source contains the old trusted-session methods, but the connected ChatGPT
`rian_eemf_owner` schema exposes only status/list/read and per-command draft
methods. The production gateway has no V2 bridge configuration. Its Outlook
trusted profile permits local metadata search, not sync or a selected body read.
Consequently the 2026-11-26 sync and subsequent search used separate generic
command approvals. The two supplied legacy action IDs did not resolve through
the current action-status MCP, so their detailed lifecycle is unverified.

The separate V2 Mac staging connector currently has no standing grants and its
only online agent, `Oui-MacStudio.local`, advertises `diag.wait` alone. PR #13
implements a one-approval mail review session in source, but it has not been
deployed to that staging service or installed on EEMFO3L. A successful Railway
deployment of the older staging image therefore does not prove the mail flow.

## This follow-up source change

- Mail review remains pending until its first approved read-only sync reports
  success and confirms no mailbox mutation. Failed, canceled or expired initial
  sync revokes the pending scope. This closes the window in which a new grant
  could search an old local index before the first sync completed.
- Six dedicated MCP entry points (`mail_status`, `mail_sync`, `mail_search`,
  `mail_read`, `mail_recent`, `mail_review_pending`) map only to validated V2 job
  kinds. The agent independently recognizes the same fixed kinds. All return
  jobs for polling with `rian_v2_job_status`; none constructs shell commands.
- Local search supports a bounded offset, ISO date range, sender, recipient and
  folder filters. Results contain metadata and a latest sync timestamp. The
  pending review helper reports a heuristic comparison against indexed Sent
  subjects; when Sent is absent it reports `SENT_NOT_INDEXED` instead of claiming
  unanswered mail.
- The OAuth gateway forwards only the six named mail methods in addition to
  its existing `rian_v2_*` tools. The original production source and deployed
  service have not been changed.
- The V2 local agent can select `source.type=outlook_bridge_v1` with an owner-set
  absolute `root` for the installed Outlook Bridge. It reuses the Bridge's
  validated ECOUNT configuration and Windows Credential Manager secret in the
  local process. Neither credential nor raw mailbox batch is returned to the
  gateway. The agent's `mail.account_fingerprint` must match the Bridge account;
  `legacy_index` can point to the Bridge's existing local index for seeding.
  A partial folder fetch fails the sync instead of activating a review grant.

## Release gates

1. Review the complete diff and run CI across Windows, macOS and Linux, including
   gateway build and real process tests. The local Node/Python tests are only a
   subset of that gate.
2. Rehearse a separate staging deployment with synthetic mail and a staged
   agent that explicitly allows the mail kinds. Preserve the current diagnostic
   Mac agent and its existing volume; take a database backup before migration.
3. Confirm employer approval for ECOUNT mailbox processing and retention.
   Install the V2 agent on EEMFO3L with a device-specific token and mailbox
   configuration after owner review. The local Outlook Bridge adapter was
   instantiated on EEMFO3L without reading mail or exposing its credential,
   but no V2 agent has yet run against that account. Proton requires a separate
   mailbox profile and authorization; this change does not claim Proton parity.
4. Deploy the reviewed gateway and V2 server with a recorded rollback deployment,
   reconnect the ChatGPT MCP so the six names appear, and execute the actual
   sync → recent/search → selected read → sent comparison workflow without
   another approval under an explicitly approved scope.
5. Exercise grant expiry/revocation, cross-device and cross-account denial, and
   Level 2 operations before calling the release PASS. General fleet Git/search
   read tools and Level 1 development permissions are separate unfinished work.

Rollback: use Railway's previous successful deployment IDs for the affected
staging/production service, disable V2 agent mail kinds on the PC, and revoke
the corresponding review grant. Do not roll back the SQLite volume by deleting
it; preserve an encrypted backup and audit history.
