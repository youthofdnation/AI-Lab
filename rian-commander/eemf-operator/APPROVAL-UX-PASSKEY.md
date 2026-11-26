# Owner approval UX: passkey design gate

Status: implemented in the PR #14 EEMFO3L V2 staging code. Production permission is
not enabled. Actual Windows Hello, Touch ID, mobile authenticator, ChatGPT MCP,
and Railway persistence checks still require live staging verification.

The fixed management URL is `https://rian-v2-eemf-mail-stage-staging.up.railway.app/v2/permissions`.
It lists pending, approved, and expired requests, active device/account grants,
recent jobs, and approval audit records. It polls while open. The MCP returns
this URL and exposes `rian_v2_policy_status` so a waiting ChatGPT session can
observe completion without asking the owner to report it in chat. A closed
ChatGPT session is not automatically resumed.

The implementation uses pinned `@simplewebauthn/server` and
`@simplewebauthn/browser` packages. The initial owner password authenticates
passkey enrollment or recovery. Passkey login and each approval use separate,
short-lived, single-use challenges. Policy approval binds tenant, owner, OAuth
client, device, account, requested scope, selected scope, duration, and limits.
Server verification requires the expected HTTPS origin, RP ID, user verification,
signature, and stored credential counter. Sessions, challenges, credentials,
and policy grants persist in the existing encrypted SQLite volume. Revocation
is immediate. The server does not offer an MCP approval tool.

Read-only policy changes create a pending replacement and leave the old grant
active until the owner approves the new scope. The replacement then revokes the
old grant atomically. The four periods are 24 hours, 7 days, 30 days, and until
revoked. Mail send, delete, move, and arbitrary shell are excluded.

Rollback: restore the previous stage image pinned to `a9e6979` and retain the
existing volume. The new SQLite tables and column are additive; the old image
uses schema version 3 and ignores them. A remote volume backup/restore must be
verified before treating the staging migration as recoverable in practice.

## Immediate behavior

The existing read policy still needs one explicit owner approval. The staging
approval form stays on the page after submission, shows a clear result, and can
be reopened to confirm the same grant without creating another request. A
pending request's original link remains usable for at most 24 hours. The
password fallback remains rate limited and bound to the exact request.

## Password replacement for later approvals

Use WebAuthn passkeys, which can invoke Windows Hello, Touch ID, or a security
key through a supported browser. A passkey cannot be borrowed from ChatGPT or
the old Gateway: it is bound to the RIAN approval site's relying party ID.
Enrollment therefore needs an explicit owner-authenticated ceremony once.
The password remains the recovery method, not an automatically submitted input.

1. Give the staging approval host a stable HTTPS domain. Bind the RP ID and
   expected origin to that host; reject other origins, hosts, and staging to
   production credential reuse.
2. Add an owner-only enrollment screen. Verify the existing owner password,
   then generate a one-use registration challenge. Require user verification,
   prefer a platform authenticator, and store only the credential ID, public
   key, counter, transports, owner, tenant, RP ID, creation time, and status in
   the persistent encrypted volume. Never log the password or challenge.
3. For approval, generate a short-lived one-use challenge bound to the exact
   request ID and a digest of tenant, owner, OAuth client, device, account or
   project, allowed features, duration, and limits. Verify the passkey
   assertion, origin, RP ID, user verification, signature, counter, and stored
   credential status before atomically consuming the challenge and approving.
   There is still no MCP approval tool.
4. Show the exact scope and outcome in the owner UI. Reopening the link shows
   the current grant state. Revocation remains immediately available through
   the authenticated owner connection. Passkey removal requires fresh owner
   verification and is audited.
5. Run negative tests for challenge replay, cross-owner and cross-tenant use,
   wrong OAuth client, changed scope, origin/RP mismatch, counter rollback,
   expiration, revocation, restart, concurrent submit, and password fallback.
   Test Windows Hello and Touch ID on actual devices before enabling them.

Registered-device approval notifications need their own signed request and
explicit human confirmation. An agent token or an OS-unlock check alone must
not be allowed to approve a grant.

References: [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/),
[SimpleWebAuthn server](https://simplewebauthn.dev/docs/packages/server),
[SimpleWebAuthn browser](https://simplewebauthn.dev/docs/packages/browser),
[Microsoft passkeys](https://learn.microsoft.com/en-us/windows/security/identity-protection/passkeys/),
[Apple passkeys](https://developer.apple.com/documentation/AuthenticationServices/supporting-passkeys).
