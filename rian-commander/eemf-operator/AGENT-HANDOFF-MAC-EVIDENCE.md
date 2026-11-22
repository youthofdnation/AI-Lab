# Agent Handoff — Mac Studio evidence (2026-11-22)

Host: Oui-MacStudio (macOS 26.7.3, Apple M1 Max). Node 26, Claude Code 2.1.330 (CLI bundled
with the desktop app, headless `-p`), codex-cli 0.164.0 (ChatGPT login).
Target: a **disposable** Git repository created for this test (README + .gitignore only);
`.claude/settings.local.json` and `.rian-handoff/` git-ignored. Private store outside the repo.

**Trigger caveat:** no real Claude Code usage limit occurred. The `StopFailure` event was
synthetic: the official field set (`hook_event_name`, `error: "rate_limit"`, `error_details`,
`last_assistant_message`) with the real `session_id` of the Claude session that produced the
checkpoints, piped into the exact hook command from the settings file. Everything else was real.
This is **not** evidence of an automatic switch on a real rate limit.

## 1. Official Claude hooks in a real Claude Code session

| Step | Observed |
|---|---|
| Real session before owner approval | `SessionStart`, `UserPromptSubmit`, `PostToolUse` fired; each recorded `BLOCKED ACTIVATION_NOT_APPROVED (APPROVAL)` |
| Owner approval | interactive terminal, owner typed `APPROVE <digest>`; scripted approval is refused (`INTERACTIVE_OWNER_TERMINAL_REQUIRED`) |
| Real session after approval | the same three hooks wrote incremental checkpoints, sequence 1 → 2 → 3 |

## 2. Real Codex runs through the hook command

| Run | Task | Result |
|---|---|---|
| A (synchronous, before P2.1) | create `HANDOFF_RESULT.md` with one line | `COMPLETED` in 34 s, Codex thread `01a2024d…`, file exactly `handoff ok\n`, no other change, lease released |
| B (detached, P2.1) | create `HANDOFF_INVENTORY.md` from `git ls-files` | hook returned in **0.21 s** (`DISPATCHED_DETACHED`); detached runner `COMPLETED` in 35 s, Codex thread `01a20254…`; content exactly as required; runner exited; lease released |

Negative checks on the real setup: a repeated rate-limit trigger for the same session →
`AUTOMATIC_DISPATCH_ALREADY_ATTEMPTED (EXECUTION)`; `StopFailure` with `server_error` → `IGNORED`;
an edited manifest → `CHANGED_REAPPROVAL_REQUIRED` until the owner approves again; a completed
task → `PROJECT_TASK_ALREADY_ATTEMPTED` (no replay).

## 3. Found on the device and fixed in this branch (P2.1)

- Codex ran inside the Claude hook process, capped at 120 s by the budget and 180 s by the hook
  timeout — real development work would be killed and left `UNKNOWN_DO_NOT_RETRY`. Now a detached
  runner executes the single claim (budget up to 30 min) after re-checking seal and worktree.
- `StopFailure` output is ignored by Claude, so blocked handoffs were invisible, and a missing seal
  or checkpoint surfaced as `UNSAFE_PRIVATE_RECORD`. Now: `ACTIVATION_NOT_APPROVED`,
  `CHECKPOINT_MISSING`, a per-worktree hook status record and `automatic-handoff-cli.mjs status`
  with `APPROVAL` / `CHECKPOINT` / `EXECUTION` / `CONFIGURATION` categories.
- An ignored stop or a rejected duplicate no longer hides the last real dispatch outcome.

Tests: `node --test agent-handoff.test.mjs manual-handoff.test.mjs automatic-handoff.test.mjs`
→ 28/28 on the Mac (25 existing + new status, CLI, detached and budget tests).

## Not verified

- A real Claude Code rate-limit `StopFailure` (requires actual usage exhaustion).
- Hooks in Claude **desktop app** sessions (the CLI was used; the docs state the same events fire).
- Windows and Linux real-device runs (CI matrix only).
- Activation on a real project; the Codex → Claude return path (P3).
