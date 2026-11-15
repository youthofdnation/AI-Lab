# RIAN Commander D23 restricted runner — development branch

This is a source-controlled development prototype, not an installed remote runner.

Existing 1Q Commander: read-only and unchanged (can_exec=false, can_write=false).
Existing four-PC MCP: read-only and unchanged.

Objective:
- A separate 1Q-local runner accepts exactly D23_AUDIT_READONLY_V1.
- Task manifests require HMAC-SHA256, 5-minute expiry, nonce replay protection, and device ID match.
- Local runner executes only fixed observational commands (GPU memory, Python process inventory).
- Writes a result JSON under C:\Users\M\salpion-d23-readonly.
- D23 remains UNKNOWN without stronger evidence; no training, checkpoint modification, subprocess termination, or llama-server restart.
- The remote broker, per-runner enrollment, durable queue, dual authorization and installation have NOT been built. Do not submit arbitrary commands through the existing read-only MCP.

Security acceptance criteria:
1. Unknown task names, alternate devices, extra fields, altered signatures, expired requests and duplicate nonces must fail.
2. No secret is embedded in this repository or returned in status JSON.
3. Existing 1Q agent access rights remain unchanged.
4. Require manual, explicit installation approval for any 1Q service.
5. New remote task endpoint must not reuse the fleet:read OAuth scope.

The generated local prototype ZIP is a separate test artifact. Track runner and broker implementation in a follow-up PR before production deployment.
