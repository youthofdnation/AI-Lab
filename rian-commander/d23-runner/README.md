# RIAN Commander — 1Q D23 restricted job channel (development)

## Purpose
A scoped extension for DESKTOP-1QGT8D6. It does NOT change the existing Commander fleet's read-only tools or 1Q agent permissions (`can_exec=false`, `can_write=false`).

**Deployment status (2026-11-15):** The isolated broker is deployed on Railway with a dedicated 1GB persistent volume, but the 1Q runner is **not installed or enrolled**. No remote execution has occurred. Do not claim 1Q remote execution is ready.

### Components

- `runner.py`: verifies a five-minute HMAC-SHA256 manifest with strict task/device allowlist and persistent nonce replay protection; executes only fixed read-only GPU and process observations; writes to `C:\Users\M\salpion-d23-readonly\`.
- `broker.ts`: SQLite-backed durable jobs; fixed task type, explicit approval, one-time leasing, expiry and completion metadata.
- `broker-server.ts`: separate broker API protected by *three distinct credentials* (operator, approver, runner). The fleet OAuth `fleet:read` credential cannot submit jobs.
- `runner_client.py`: explicit one-shot `--once` polling; requires HTTPS, blocks redirects and unknown endpoints, checks signed manifest before observation, then acknowledges completion.
- `install-local.ps1`: Windows-only, defaults to verification without installing; explicit `-Install` copies verified files to the current 1Q user's application-data directory, with **no background startup** and no credentials.
- `test_*.py`, `broker.test.ts`: Windows/Linux runner tests, Bun job broker tests, Windows installer syntax check.

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

### Deployed isolated broker (2026-11-15)

- Service: `rian-d23-restricted-broker` (Railway project `rian-commander`)
- Public hostname: `rian-d23-restricted-broker-production.up.railway.app`
- Database: persistent `/data/d23-jobs.sqlite`, separate `rian-d23-broker-data` volume (1 GB)
- Health endpoint: `GET /health`
- No task submission or approval is exposed via the existing fleet read-only MCP.
- **Safe live tests completed:** no-auth and wrong-role requests refused, arbitrary task/device rejected, requests remain unapproved, jobs persisted through a broker redeploy, no runner lease/remote execution occurred.
- Temporary verification service removed after tests.
- Staged production credentials live only in Railway variables; DO NOT place them in documentation or chat.
- 1GB Railway persistent storage and broker compute can add usage charges.
- The unapproved test job remains in the database until the defined 600-second expiry is checked and processed; it cannot be leased without separate approval.

### Missing before release
1. Independent security review; operational lease reconciliation, multi-instance locking, rate limits and operator audit.
2. **Completed on 2026-11-15:** a dedicated Railway broker was deployed with separate operator/approver/runner/signing secrets and 1GB /data volume. HTTP checks passed for anonymous denial (401), wrong-role denial (401), unsafe device/task denial (403), no-job lease (null) and unapproved-job lease (null). SQLite pending job persisted across a broker redeploy.
3. Explicit local admin installation/enrollment of the 1Q runner and secure task signing key.
4. Run 1Q mock/observation end-to-end and show status JSON read through the existing fleet MCP.
5. Add ChatGPT operator/approver workflows under a new narrowly scoped permission. Never elevate `fleet:read` to execution.

No D23 full training, 1Q software installation, source deletion or production changes occur merely from these files.


### 2026-11-15 one-time enrollment development

- Deployed a new **1Q-only** invitation API to the isolated Railway D23 broker without changing the existing read-only MCP.
- `POST /v1/d23/enrollment/invite` requires the operator credential and a matching device, then creates one 10-minute invitation. Do not log invitation codes.
- `POST /v1/d23/enrollment/claim` verifies and consumes the invitation once, delivering runner credentials only over HTTPS. This is a device onboarding prototype; production should additionally use device attestation, throttling and credential rotation.
- `enroll-local.ps1` prompts for the code locally on 1Q and stores credentials under the current Windows user's DPAPI protection (no secrets printed).
- `run-once.ps1` defaults to verification; an explicit `-Run` enables one allowlisted observation cycle after a separate task approval.
- `bootstrap-1q.ps1` downloads pinned GitHub files and validates Git blob hashes; defaults to **verification only**, and `-Install` performs a local installation without enrollment, scheduling, training or changing the existing Commander agent.
- GitHub Actions on Windows/Linux and Bun completed successfully on commit `3b35253b70b5`.
- **1Q installation, enrollment and live remote job end-to-end checks remain NOT DONE.** Desktop Commander currently reports 1Q offline; the ChatGPT environment doesn't expose 1Q RIAN Commander tools.

Operator must issue enrollment code only after the user confirms the runner's verified local installation; it expires after ten minutes. Do not include operator credential or signing keys in a chat or shell command.


### Separate ChatGPT D23 operator MCP deployed (2026-11-15)

- URL: `https://rian-d23-operator-mcp-production.up.railway.app/mcp`
- Railway service: `rian-d23-operator-mcp` (separate from fleet's `rian-commander-oauth-gateway`)
- Scope: `d23:request` (fleet read-only scope `fleet:read` remains unchanged and inaccessible through this service).
- Tools: `rian_d23_request_audit`, `rian_d23_job_status`, `rian_d23_read_result`.
- **ChatGPT MCP tools cannot approve, execute arbitrary commands, modify files or start D23 training.** Request returns a browser-only approval URL. Human owner enters the existing owner password on that separate approval page; only then does the broker receive approval for one allowlisted observation.
- Railway staging applied, deployment SUCCESS. Live test confirms health=200 ready=true, d23 scope metadata=200, anonymous MCP=401, authorized loopback OAuth client registration=201, disallowed callback=400. Temporary live test function deleted.
- Approval flow and new MCP tools are **not yet tested end-to-end in ChatGPT/Codex**; explicit client registration/login remains.
- 1Q one-shot D23 Runner is already installed and enrolled and previously completed one approved observation E2E. Automated polling is **not installed**; the operator must explicitly enable the 1Q scheduled task.
- Auto-poller source: `enable-poller.ps1`. For permitted manual installation, download the file from a pinned GitHub commit into `C:\Users\M\AppData\Local\RIANCommander\D23RestrictedRunner` and run `& ...\enable-poller.ps1 -Enable`. In read-only mode it reports task status without changes; `-Disable` removes it.
- Latest automated checks on Windows, Linux and Bun: `eba7238426e4aa7d0c72291348c3d62179df35d2` workflow succeeded.
- Local remote command tools were blocked by Desktop Commander subscription quota; no remote write/task creation was attempted after the quota failure.
- Separate approval UI requires user interaction. Do not paste owner password or API tokens into the chat or store them in GitHub.
