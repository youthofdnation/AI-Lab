# Repeated approval investigation and implementation status (2026-11-26 KST)

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

## Release gates

1. Review the complete diff and run CI across Windows, macOS and Linux, including
   gateway build and real process tests. The local Node/Python tests are only a
   subset of that gate.
2. Rehearse a separate staging deployment with synthetic mail and a staged
   agent that explicitly allows the mail kinds. Preserve the current diagnostic
   Mac agent and its existing volume; take a database backup before migration.
3. Confirm employer approval for ECOUNT mailbox processing and retention.
   Install the V2 agent on EEMFO3L with a device-specific token and mailbox
   configuration after owner review. Proton requires a separate mailbox profile
   and authorization; this change does not claim Proton parity.
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
