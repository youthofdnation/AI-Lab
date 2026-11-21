# RIAN Agent Handoff — Claude Code ⇄ Codex

**State:** source-only P0 foundation, NOT installed, NOT enabled on any PC.
**Branch:** feature/rian-commander-agent-handoff-mvp
**Scope:** cross-provider dev task handoff; separate from V2 mail/diagnostic actions.

## Goal

When Claude Code reaches a rate limit, RIAN Commander will retain the task and
Git worktree, then allow an explicitly authorized Codex worker to continue.
Later, the reverse adapter can hand back to Claude Code. This does NOT transfer
hidden model reasoning, proprietary session state, paid quotas or credentials.
The receiving provider creates its own session with the captured work context.

## Trigger

Claude Code has an official StopFailure hook with error=rate_limit. Only this
structured event is recognized for automatic provider exhaustion. Billing,
authentication or account-hold errors require owner attention. Generic CLI
failures, timeouts and UI usage warnings do NOT automatically switch.

Independent Claude desktop/cloud conversations may not be supervisable through
a local CLI hook. Use supported session export, worktree snapshots or a manual
handoff button for those. Never scrape private billing pages or cookies.

## P0 implementation (this branch)

- agent-handoff.mjs: classifyClaudeStop() — strict rate-limit event classifier
- inspectWorktree() — read-only Git commit, branch, changed-path metadata
  within a scoped owner-approved directory; no raw diffs or secret paths
- buildHandoff() — owner task goal, next actions, test summaries, safe grants;
  refuses unknown/running jobs and unapproved source/destination providers
- saveLocalHandoff() — atomic, local-only JSON checkpoint (0700 directory and
  0600 file on POSIX); does not commit, stash or upload any code
- planCodexHandoff() — produces a structured argv/stdin plan for
  codex exec --json --sandbox read-only|workspace-write --cd PATH -
  and requires ownerApproved=true. It DOES NOT launch the CLI.

The checkpoint contains no Claude transcript or Git diff. Owner-provided notes
also require local secret scanning before any cross-provider transmission.
Provider authentication remains independent.

## Gates before automatic execution

1. A separate repo-scoped development runner with signed, revocable owner grants.
   Never silently expand the existing V2 mail/diagnostic allowlist to arbitrary
   shell execution.
2. Trusted Claude Code CLI or Agent SDK integration, including StopFailure hook
   and incremental checkpoints captured *before* usage is exhausted.
3. Exclusive per-repo/worktree single-writer lease; unknown jobs or stale
   sessions must fail closed without replaying commands.
4. Owner-visible handoff preview and permission boundary; approved targets,
   time/operation budgets and sandbox. Prevent destructive commands, pushes,
   deployments, credential access and paid API calls without separate approval.
5. Local-only sanitized transcripts if explicitly enabled. Avoid reading
   private auth stores, such as ~/.claude and ~/.codex. Never copy tokens.
6. Receiver authentication and availability checks for Codex. Support Codex
   SDK/app-server for interactive orchestration or codex exec --json for bounded
   tasks. Capture progress, result and Codex session ID.
7. Real Mac + Windows E2E: fake rate-limit, dirty/untracked worktree, active
   writer, duplicate trigger, checkpoint crash, denied owner scope, failed
   Codex auth, loss of network, quota exhaustion and reverse-provider handoff.
8. UI opt-in per project (default OFF), live provider indicator, manual switch,
   stop button, approval timeline and recovery state.

## Phases

P0: classifier + safe Git metadata + source-only launch plan (this PR).
P1: manual Claude → Codex switch using synthetic local worktree.
P2: owner-approved automatic switching from official rate-limit events.
P3: Codex → Claude return, Mac/Windows packaging, tenant isolation E2E.
P4: separate privileged remote development surface and UI.

Do NOT deploy or enable automatic execution in production from this branch.

References:
https://code.claude.com/docs/en/hooks
https://code.claude.com/docs/en/headless
https://code.claude.com/docs/en/sessions
https://learn.chatgpt.com/docs/cli/reference
