# P2 opt-in Claude Code → Codex handoff

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
  "budget": {"timeoutMs": 120000, "checkpointMaxAgeMs": 900000}
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

The `codexReceiver` adapter is isolated so a future Codex → Claude path can
have its own trigger, grant, preflight, and process runner. No V2 mail or
diagnostic command allowlist is changed.

References: [Claude Code hooks](https://code.claude.com/docs/en/hooks),
[Codex CLI reference](https://developers.openai.com/codex/cli/reference).
