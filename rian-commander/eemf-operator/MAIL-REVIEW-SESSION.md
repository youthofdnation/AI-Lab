# RIAN Commander V2 — One-approval work-mail review sessions

**Status: Draft PR #13, source only. Not deployed.** No real mailbox was accessed.

## Problem
The prior exact-scope grant only matched identical sync/search parameters; a
different search query and every mail body read caused another approval prompt.

## Owner flow
1. Start the existing rian_v2_start_job with kind mail.sync and bounded
   parameters (for example days=14, maxMessages=200).
2. In the owner-password browser approval form, optionally check
   **업무메일 연속 검토** and select 1–60 minutes and 1–60 additional jobs.
   Default scope is 30 minutes / 30 extra calls.
3. Mail body access is **disabled by default**. To permit it, explicitly check
   the separate body-access box and select at most 20 one-message reads.
4. From the same authenticated OAuth client, tenant, owner and device,
   additional mail.sync requests within the approved bounds and varied
   mail.search queries are approved automatically without another prompt.
5. Explicitly permitted mail.read can access only an ID from a successful
   search in the same review session, reported as recent enough for the
   initial approved day range. The ID is consumed after that read.
6. Use the existing rian_v2_list_grants tool (kind=mail.review.readonly) to
   view grant status and rian_v2_revoke_grant to revoke it immediately.
   Revocation cancels queued jobs and requests a safe stop for running ones.

## Safety scope
- Device, tenant, owner, hashed OAuth-client reference and time/job budgets
  are enforced by the durable server.
- Mailbox is always read-only (IMAP EXAMINE and BODY.PEEK). A sync changes
  local index/backup only; it never changes original mailbox data.
- Searches return subject, sender, date, folder and message ID metadata only.
  The previously cached index can include messages older than the current
  review window (the owner page states this explicitly).
- Bodies are at most one selected message per job and retained encrypted in
  the queue for at most one hour. No attachments are transferred.
- Message IDs allowed for body reads are stored as SHA-256 digests and the
  server only accepts successful agent search results within the age limit.
- No sending, deleting, moving, flagging, raw shell, path access, or other-PC
  access is added. Different OAuth clients cannot deduplicate each other's
  pending review jobs; different owners within the same tenant cannot
  list/read/cancel another owner's jobs.
- Expired/revoked sessions never authorize a fresh agent claim.
- Existing one-message exact approval and exact-params standing grants are
  preserved for requests outside a review session.

## Deployment gates
1. Peer-review authorization, CSRF, SQLite, deduplication, body scope, and
   safe cancellation tests. All relevant Windows/Mac/Linux CI should pass.
2. Real browser and synthetic mailbox/tenant E2E on separate Railway staging.
3. Confirm work-mail access is authorized by the employer.
4. Obtain explicit owner approval before any production service change or
   EEMFO3L agent install. Current deployed EEMFO3L connector still uses the
   old per-command approval system; source changes alone do not fix it.
5. Refresh ChatGPT tool discovery if changed tool descriptions are not shown.
6. Final acceptance: one browser approval, sync latest mail, varied searches,
   select only recent bodies, prepare pending-work list, revoke, and verify
   no mailbox writes or repeated browser prompts.

A future metadata-only list-recent operation could make reviewing all
messages more comprehensive. This PR does NOT claim the user's 108
indexed messages were analyzed, and does not silently send replies.
