# RIAN Commander Claude Code → Codex handoff

## P2.2 project standing grants (Issue #9, recommended)

**Status:** P2.2 is implemented in source and opt-in only. No live project hooks
or grants are installed by this PR. A live Claude Code usage-limit event
has **not** been observed end-to-end. Mac tests use a simulated structured
rate-limit event and real Codex in a disposable project; CI uses a fake Codex.

**The owner should not have to type `APPROVE <digest>` for every task.** Instead,
the grant UI asks for one explicit click per device + canonical Git worktree.
The same grant covers distinct future owner requests in that worktree, subject
to its limits: at most 20 handoffs, 30 days, and 30 minutes per handoff.
The owner can revoke it immediately. Changing devices or worktrees, an expired
or exhausted grant, or an unsafe task requires a new approval or blocks work.

The approval dialog shows the device, exact worktree, provider pair, sandbox
write permission, no-network/no-push/no-deploy/no-credentials policy, duration
and run count. macOS uses a native dialog (Approve / Decline), Windows uses a
native Yes/No dialog. Linux falls back to an interactive owner confirmation.
**An initial consent is still required; the program must never forge a click.**
An approval for a throwaway sandbox does not authorize the real project.

Local CLI operations (developer/operator documentation; NOT instructions to
repeat a typed approval for every task):

```sh
# One-time explicit owner consent for a dedicated development worktree
node automatic-handoff-cli.mjs grant --worktree "/ABS/PROJECT" --runs 5 --days 7 --run-minutes 20
# Safe read-only readiness and last-trigger diagnostics
node automatic-handoff-cli.mjs status --worktree "/ABS/PROJECT"
# Revoke immediately without an approval dialogue
node automatic-handoff-cli.mjs revoke --worktree "/ABS/PROJECT"
# Preview the exact project-local Claude hook settings (JSON output only)
node automatic-handoff-cli.mjs install-plan --worktree "/ABS/PROJECT" --runtime "/ABS/FIXED/automatic-handoff-cli.mjs"
```

After the owner approves, the developer must still install the Claude Code
**project-local** hooks explicitly. `install-plan` prints a JSON preview with
`settingsPath`, `existingSettings`, and `settings`; it does not create a grant,
write settings, or activate hooks. Review the `settings` object and merge it
with any existing `.claude/settings.local.json`, preserving its other entries.
The runtime argument must point to a **fixed, reviewed copy of the handoff
runtime outside the editable worktree**. If the grant uses a custom store,
include the same absolute `--store` path in the preview command. All five hook events
(`SessionStart`, `UserPromptSubmit`, `PostToolUse`,
`PostToolUseFailure`, and `StopFailure` with `rate_limit` matcher) must
invoke `automatic-handoff-cli.mjs hook-grant` with the hook JSON on standard
input. The latter uses the official event's `cwd` to identify the exact worktree;
it must not accept a different worktree from a remote sender. The current
`automatic-handoff-hooks.sample.json` documents the older per-task
`--manifest` flow, **not** the new standing-grant installation. Do not replace
a global Claude settings file.

The `UserPromptSubmit` hook saves the owner's last request locally, with
sensitive-looking text refused. On an official `StopFailure(error=rate_limit)`,
a fresh same-session checkpoint, unchanged Git content, non-overlapping
writer lease, valid grant, and unused task/run slots are required. Codex
starts as its **own** session and receives the task and Git state, not
Claude's hidden conversation/thoughts or either provider's credentials.
For each distinct request the prior grant is reused without another dialog.
Duplicate event/prompt, unsafe prompt, revoked or exhausted grant, and
uncertain execution all fail closed. Never auto-retry an ambiguous job.

Both the legacy manifest and project-grant paths remain supported.
The manifest flow below uses a per-task digest seal and its own interactive
`APPROVE` prompt; do not use it when the product goal is project-level consent.
Existing remote V2 mail/diagnostic allowlists, production systems, and
other worktrees must not be modified to install this feature.

### Validation required before real-project activation

- Fix platform CI failures first; all macOS, Windows, and Ubuntu suites must
  pass for the exact PR head being deployed.
- Test the native approval click, two different owner prompts and **real**
  Codex handoffs in one disposable Mac Git worktree with no new approval
  between tasks. Verify task receipts, uncommitted files and single-writer
  behavior, plus revoke/expire/duplicate handling.
- Confirm the actual Claude Code session can load the project-local hooks.
  A synthetic `StopFailure` is not evidence of a real usage-limit event.
- Only then consider deploying to the named real development worktree,
  showing an owner-friendly scope preview once. No production deployment,
  forced restarts, or changes to other running apps are implied.

---

## P2 manifest-bound per-task handoff (legacy; retains original behavior)



**Source only.** These hooks are examples and are not installed. P1 manual
handoff remains available. No real Claude rate limit was observed during P2
development; tests use synthetic hook events and a fake Codex executable.

The owner creates `.rian-handoff/activation.json` at the **exact Git worktree
root**, with a fixed task and budgets. Example (replace absolute paths and
task text, then review the complete file):

```json
{
  "schema": "rian-auto-handoff/v1",
  "enabled": true,
  "project": {"approvedRoot": "/absolute/owner/scope", "worktree": "/absolute/owner/scope/project"},
  "task": {"taskId": "task_12345678", "goal": "Finish the approved development task", "pendingSteps": ["Review Git status"], "testSummary": []},
  "permissions": {"workspaceWrite": true, "exclusiveWorktree": true, "allowedProviders": ["claude", "codex"]},
  "budget": {"timeoutMs": 1200000, "checkpointMaxAgeMs": 900000}
}
```

Run `node automatic-handoff-cli.mjs approve --manifest /absolute/.../.rian-handoff/activation.json`
in an interactive owner terminal. It previews the task, permission, and budget,
then writes a digest seal into a private local store outside the project.
Changing the manifest invalidates the seal. The owner must dedicate the worktree
to this handoff; the hook cannot prove that unrelated IDEs or agents have
stopped writing.

The uninstalled sample in `automatic-handoff-hooks.sample.json` shows the
official `SessionStart`, `UserPromptSubmit`, `PostToolUse`,
`PostToolUseFailure`, and `StopFailure` command hooks. Replace placeholders,
review them, and install through Claude Code's normal hook configuration only
if this project is approved. Run Claude from the exact worktree root. Hooks
receive JSON on stdin; the runner ignores prompts, tool arguments, transcripts,
and error text. Incremental checkpoints contain Git metadata and a digest of
dirty content, not source contents. A checkpoint must precede the rate limit
event, match its session, and be fresh. Only structured `StopFailure` with
`error=rate_limit` dispatches.

The dispatch marker is created exclusively per worktree and Claude session,
and a separate task marker prevents another Claude session from replaying the
same approved task. A changed task requires a changed manifest and a new owner
approval. The marker is never deleted automatically. It is created
before launching. P1's per-worktree lease, Codex version/login checks,
workspace sandbox, timeout, and single-attempt receipt are reused. Progress
records contain counts, state, Codex thread ID, changed path metadata, and
counts of command and recognized test checks; raw provider output is
discarded. Failed authentication, missing checkpoints, changed worktrees,
network uncertainty, usage limits, and crashes do not trigger a blind retry.
If the lease is retained, inspect the receipt and processes, then use
`node automatic-handoff-cli.mjs recover --manifest ABSOLUTE_PATH --handoff-id UUID --reason "..."`
from an interactive owner terminal. Recovery writes an audit record, releases
only the matching lease after process verification, and does **not** replay the
same session. A new owner-approved task/session is required to run again.

The automatic receiver forces noninteractive approval rejection, disables
workspace command network access and web search, requests a ChatGPT login,
and omits API-key environment variables. Review account-level integrations
and the effective Codex configuration before enabling it. A digest seal is a
local owner-approval record, not a cryptographic defense against malicious
same-user processes: Claude hook JSON has no signature, and an unrelated
same-user process could forge it. Use a dedicated worktree and host-level
process isolation where that threat matters. A real Claude/Codex integration
and a live rate-limit event remain unverified.

## Detached run, status and errors (P2.1)

The `StopFailure` hook no longer runs Codex inside Claude's hook process. It validates the
approval seal, the session's fresh checkpoint, the unchanged worktree and the single-shot
markers, writes a `DETACHED` claim and starts `automatic-handoff-cli.mjs dispatch-run` as a
detached process, then returns (about 0.2 s on the Mac Studio). The runner re-checks the seal
and the worktree fingerprint immediately before Codex starts and runs the claim exactly once
(`DISPATCH_NOT_PENDING` / `DISPATCH_RUNNER_ALREADY_STARTED` otherwise). `budget.timeoutMs` may
therefore be up to 30 minutes; the `StopFailure` hook timeout only covers validation (30 s).

Claude ignores `StopFailure` output, so every hook call records its outcome in the private store
(`hook-status/`). Ask why a handoff did or did not run with the read-only command:

    node automatic-handoff-cli.mjs status --manifest /ABS/WORKTREE/.rian-handoff/activation.json

It reports the manifest, owner approval (`APPROVED`, `NOT_APPROVED`, `CHANGED_REAPPROVAL_REQUIRED`),
the last checkpoint and its freshness, the last trigger and the last real dispatch (with the
authoritative marker state and whether a detached runner is alive), a held lease, an already
attempted task and the Codex CLI login. Exit code 0 means ready, 2 means blocked. Every blocker
and every hook error carries a category: `APPROVAL`, `CHECKPOINT`, `EXECUTION` or `CONFIGURATION`.
New explicit codes: `ACTIVATION_NOT_APPROVED`, `CHECKPOINT_MISSING`, `RUNNER_SPAWN_FAILED`.

Keep `.claude/settings.local.json` and `.rian-handoff/` git-ignored in the activated worktree;
otherwise they appear as changed sensitive paths and the handoff is refused.

The `codexReceiver` adapter is isolated so a future Codex → Claude path can
have its own trigger, grant, preflight, and process runner. No V2 mail or
diagnostic command allowlist is changed.

References: [Claude Code hooks](https://code.claude.com/docs/en/hooks),
[Codex CLI reference](https://developers.openai.com/codex/cli/reference).
