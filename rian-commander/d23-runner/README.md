# RIAN Commander — 1Q D23 restricted job channel (development)

## Purpose
A scoped extension for DESKTOP-1QGT8D6. It does NOT change the existing Commander fleet's read-only tools or 1Q agent permissions (`can_exec=false`, `can_write=false`).

It is **not yet deployed or installed**. Do not claim remote execution is ready.

### Components

- `runner.py`: verifies a five-minute HMAC-SHA256 manifest with strict task/device allowlist and persistent nonce replay protection; executes only fixed read-only GPU and process observations; writes to `C:\Users\M\salpion-d23-readonly\`.
- `broker.ts`: SQLite-backed durable jobs; fixed task type, explicit approval, one-time leasing, expiry and completion metadata.
- `broker-server.ts`: separate broker API protected by *three distinct credentials* (operator, approver, runner). The fleet OAuth `fleet:read` credential cannot submit jobs.
- `runner_client.py`: explicit one-shot `--once` polling; requires HTTPS, blocks redirects and unknown endpoints, checks signed manifest before observation, then acknowledges completion.
- `test_*.py`, `broker.test.ts`: Windows/Linux runner tests, Bun job broker tests.

### Safety invariants
- The only task is `D23_AUDIT_READONLY_V1`. Not a training trigger.
- No arbitrary `argv`, arbitrary paths, files deleted, checkpoint changes, or llama-server process changes.
- 1Q's Commander main agent remains read-only.
- Runner keys are local enrollment secrets; no tokens or real secrets in source or output.
- Broker must have a persistent SQLite file at `/data/... ` on a properly configured Railway volume; otherwise it fails startup.
- The separate broker credentials and runner signing key must be distinct and randomly generated. Never put them into chat, source or CI logs.
- Two-role approval in the prototype is enforced by separate static secrets, NOT a production per-user account identity system.

### Local tests
```sh
python -m unittest discover -v
bun test broker.test.ts
bun build broker-server.ts --target=bun --outfile=/tmp/rian-d23-broker-check.js
```

### Missing before release
1. Independent security review; robust expiry/recovery handling, multi-instance locking, rate limits and operator audit.
2. Provision a durable broker volume, set secure credentials, deploy isolated broker **without** modifying existing relay.
3. Explicit local admin installation/enrollment of the 1Q runner and secure task signing key.
4. Run 1Q mock/observation end-to-end and show status JSON read through the existing fleet MCP.
5. Add ChatGPT operator/approver workflows under a new narrowly scoped permission. Never elevate `fleet:read` to execution.

No D23 full training, 1Q software installation, source deletion or production changes occur merely from these files.
