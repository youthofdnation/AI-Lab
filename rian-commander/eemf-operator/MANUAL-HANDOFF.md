# RIAN Commander Agent Handoff — P1 local manual Claude → Codex

**Status:** P1 CLI is implemented and tested with a synthetic Codex subprocess.
**Do not confuse with:** an automatic switch for an already-open Claude Desktop chat.
The real Codex CLI, real Claude session, and the Mac Studio are **not yet
verified in this feature**. No RIAN Commander production or Railway deploy.

## Scope and proof

The host owner runs this in a terminal on Mac/Windows. Claude must have
stopped writing to the target Git worktree before the owner authorizes Codex.

- P0 reads Git HEAD, branch and changed *path metadata* only.
- P1 stores a private local checkpoint, checks the same Git state before launch,
  enforces one writer lease per worktree and one execution attempt per handoff.
- P1 checks Codex CLI version and its own login with codex login status;
  no Claude cookie, token, transcript or subscription state is copied.
- The receiving CLI is launched as a subprocess with JSONL output:
  codex exec --json --sandbox read-only|workspace-write --cd WORKTREE -
- Approval in the local CLI requires a real interactive terminal and typing
  RUN <handoff ID prefix>. A noninteractive ChatGPT/agent call is rejected.
- No shell wrapper, no yolo mode, no auto-push, no deploy.
- Progress JSON is parsed and counted without persisting full provider output
  (which may contain secret source snippets).
- On a timeout, the record becomes UNKNOWN_DO_NOT_RETRY and the per-repo lease
  remains locked; only a human can reconcile it. No blind retry.
- Staged, unstaged and untracked files are preserved rather than stashed,
  committed or reset by the handoff tool.

### Example: diagnostics-only synthetic repo on the Mac

First create a **throwaway** Git repo manually, not an active RIAN project.
Use local Claude Code only if desired to make a small uncommitted change and
then stop its session. Do not use the screenshot's ongoing Youngmin/A100 task.

The CLI lives in rian-commander/eemf-operator on PR #5.

Create a checkpoint (NO Codex process starts):

    node manual-handoff-cli.mjs prepare \
      --root "$HOME/DEV" \
      --worktree "$HOME/DEV/rian-handoff-synthetic" \
      --task-id rian_sample_0001 \
      --goal "Finish a safe synthetic README checklist" \
      --next "Review existing uncommitted files" \
      --tests "Initial git status checked" \
      --workspace-write

Take the private checkpoint path printed by prepare and preview it:

    node manual-handoff-cli.mjs preview \
      --checkpoint "/absolute/path/from/prepare.json"

Verify the **actual** Claude Code process is no longer writing to the repo
and that no background build or other agent is a concurrent writer. On an
interactive terminal only, after deciding to grant workspace-write:

    codex login status
    node manual-handoff-cli.mjs run \
      --root "$HOME/DEV" \
      --checkpoint "/absolute/path/from/prepare.json" \
      --claude-stopped

Type the displayed confirmation phrase manually. Codex executes through its
normal signed-in CLI. The first live P1 run should be on a disposable Git
worktree containing no secrets, external services or production credentials.

A simple read-only first run is also supported: omit --workspace-write from
prepare. No arbitrary changes outside the Codex sandbox are authorized.

## Evidence and distinctions

The GitHub tests use a fake executable that implements Codex CLI's version,
login, and exec protocol. The fake reads the handoff prompt and creates one
synthetic result file in a disposable Git repo. They exercise:

1. Claude's partial untracked file survives while fake Codex writes its result.
2. Missing owner consent or a still-active Claude session acknowledgment blocks.
3. Git drift after checkpoint blocks execution.
4. Secret-looking task notes / unsafe checkpoint permissions are blocked.
5. Worktree lease collision and repeated attempts block execution.
6. Read-only grants do not become write grants.
7. Timeout holds the lease and prevents automatic retry.
8. CLI preview does not execute any provider.

GitHub matrix covers macOS, Windows, Linux. This does not prove real Codex
auth or a live model has modified files.

## Security limitations and next work

- CLI confirmation is suitable only for a manual owner session. It is NOT a
  remote approval token, and must not be exposed as an unrestricted MCP tool.
- We do not fully detect **unmanaged** Claude processes, IDE extensions or
  another application writing to the repo. The owner must confirm quiescence.
- Git changed-path metadata is not a content integrity proof. A later version
  should add protected content fingerprints and a durable process supervisor.
- The credentials and provider session histories are independent; direct
  transfer of hidden Claude context is unsupported.
- A source file inside the approved repo may itself be sensitive; the owner
  must decide whether using Codex on that repo is authorized.
- Worktree lease recovery from UNKNOWN requires process-level verification
  and a separate audited unlock action. Never remove locks automatically.
- P2 is a separately approved service using Claude's structured rate_limit
  hook, a durable single-writer lease and an owner-scoped approval grant.
  It must preserve existing macOS and Windows V2 mail/diag restrictions.
