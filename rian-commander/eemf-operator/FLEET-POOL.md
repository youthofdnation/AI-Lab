# RIAN AI Fleet pool on Commander V2 (2026-11-22)

**Status: source + tests + one real two-PC run. Not deployed, no agent installed as a service,
no permission widened.** Built on `feature/rian-commander-v2-macos-agent` (`13e9220`), reusing
the V2 durable jobs instead of a new scheduler.

## What it adds

| Part | Reuses | New |
|---|---|---|
| `fleet-policy.mjs` | — | Roster from configuration only (`RIAN_STAGE_FLEET_POLICY_JSON`); mandatory denylist; `QUARANTINED` devices accept only `quarantineKinds` (inventory); data classes (`public`/`synthetic`/`private`, private needs an explicit approval flag); protected GPU processes; `recommend()` ranks PCs by fresh inventory minus reservations and gives every skipped PC its reason; `verifyGpuRelease()` |
| `durable-long-jobs.mjs` | queue, approval, grants, leases, at-most-once dispatch, recovery | Optional `fleet` policy: denylist on request **and** claim, per-PC `maxConcurrent` and `gpuSlots` (extra work waits QUEUED), priority order, reservations (`fleet_jobs`), GPU hand-back verdict on completion; a GPU that did not verifiably hand memory back only accepts `fleet.gpu_probe` |
| `long-job-kinds.mjs` | kind registry | `fleet.inventory`, `fleet.cpu_bench`, `fleet.gpu_probe`, `youngmin.qlora_probe` (never grantable: every run needs the owner's password) |
| `fleet-http.mjs` | MCP surface | `rian_v2_fleet_status`, `rian_v2_fleet_recommend`, `rian_v2_start_job` with `device:"auto"` and optional `fleet {priority,cpu,ramMiB,vramMiB,dataClass}`. Still no approve tool |
| `rian-v2-agent.py` | supervisor, detached runner, journal, local allowlist | Fleet kinds; the PC's own denylist copy is required for fleet kinds and a denied host refuses to start; `max_parallel` (1–16); runner gets an absolute config path (bug found in the real run, see below) |
| `rian_fleet_tasks.py` | — | Read-only inventory (names and numbers only, no command lines, no file contents); deterministic SHA-256 CPU work units; GPU probe that allocates in a child process and measures memory after it exits; QLoRA probe that checks the stack first and measures only with the PC-local `fleet.qlora_measure: true` |
| `youngmin_qlora_measure.py` | — | Random-weight Qwen3-8B (public architecture) in 4-bit NF4 + LoRA on synthetic token ids; no download, no data file. **Not yet executed on a CUDA GPU** |
| `fleet-pool-run.mjs` | E2E approval pattern | Test-only driver: start, approve with a synthetic test password, feed work units, wait, read audit |

The server still sends only `(kind, bounded params)`; no kind takes a path, a command, a model name or a data file.

## Real run (central node Mac Studio + one Windows PC over an SSH-encrypted tunnel, loopback service, synthetic data)

| Check | Result |
|---|---|
| Inventory on both PCs | SUCCEEDED (after the runner config-path fix) |
| Denylisted PC / quarantined PC / private data to a non-approved PC / kind not allowed / GPU kind on a GPU-less PC | `DEVICE_DENIED` / `DEVICE_QUARANTINED` / `DATA_CLASS_NOT_ALLOWED` / `KIND_NOT_ALLOWED_FOR_DEVICE` / `KIND_NOT_ALLOWED_FOR_DEVICE` |
| 16 CPU work units, one PC (limit 4) | 45.0 s |
| Same 16 units, pool with `device:"auto"` (12 + 4) | **29.9 s (1.5x)**, every digest identical to the single-PC run |
| Tunnel cut for > lease while a job ran | `UNKNOWN_DO_NOT_RETRY`, then the late result accepted; dispatched 1x, started 1x |
| Supervisor `kill -9` mid-job (runner kept running) | restarted supervisor collected the same runner's result; dispatched 1x |
| Runner lost with its supervisor | `INTERRUPTED`, never re-run; dispatched 1x |
| Central service `kill -9` mid-job | `runningPreserved: 1`, result collected; dispatched 1x |
| GPU probe / QLoRA probe where an unnamed GPU process may be a protected service | refused before any allocation; GPU memory 671 → 671 MiB, verdict `VERIFIED` |
| All 41 jobs of the run | max dispatch per job = 1 |

Bug found by the real run: the detached runner starts in its job directory, so a relative
`--config` path broke it (`INTERRUPTED`, correctly not re-run). Fixed and covered by a test.

## Tests

`fleet-pool.test.mjs` (9), `rian_fleet_tasks.test.py` (9), plus all existing V2 suites
(Node 76/76 together, agent/mail/artifact Python suites, real-process E2E) pass on Windows.

## Not done (needs the owner)

- Deploying the fleet service anywhere but a loopback test, installing agents as services,
  changing Commander V1 permissions, firewall changes.
- Agents on PCs this session could not execute on.
- Any GPU allocation on a PC whose GPU serves production; the QLoRA measurement itself.

## Follow-up: throughput placement and a real workload (branch `feature/rian-commander-v2-fleet-throughput`)

- Placement uses measured seconds per work unit per PC and kind (median of finished jobs) and picks the
  earliest expected finish; an unmeasured PC is explored with one job at a time. `placement:"cores"`
  keeps the first version for comparison. PCs may queue up to 2 x maxConcurrent (capped by the per-PC
  open-job limit); claims still run maxConcurrent at once.
- `fleet.blob_verify`: a PC hashes its own content-addressed store (Ollama `sha256-<hex>` or Hugging Face
  hub blobs) named in its own config; results are counts, bytes, speed, mismatched names.
- Fleet suites now run inside CI-run files (imports), since the workflow file cannot be changed here.

Real run (same two PCs, loopback service, SSH tunnel; 64 synthetic units x 40, then real public-model stores):

| Run | Wall time |
|---|---|
| One PC, at most `maxConcurrent` open jobs | 176.5 s |
| **One PC, same queue depth as the pool (fair baseline)** | **103.9 s** |
| Pool, cores placement (first version) | 120.9 s (16 % slower than the fair baseline) |
| **Pool, throughput placement** | **90.6 s (13 % faster)**, digests identical in all four runs |
| Store integrity, 32.3 GB / 37 public-model files on both PCs, parallel (cold cache) | **22 s**, 0 mismatches |
| Same stores one job at a time (partly warm cache) | 56 s |

The first "1.5x" of the 16-unit run compared against the no-queue baseline; against the fair baseline the
two-PC gain for CPU units is 13 %, bounded by the second PC being ~3x slower per unit. Verifying a store
where it lives moved only job JSON over the network; pulling the second PC's 16.9 GB to one PC at the
measured 6.6 MB/s would have taken ~44 min of transfer alone. All 266 jobs of the run: dispatched once each.

## Follow-up: memory guard for PCs that serve other work

A fleet PC may already run its own services (a model server, another project's containers). One such PC
was measured with under 1 GB of 32 GB available; sending it ordinary work would push those services into
paging. The fleet therefore treats memory as the PC's first, not the fleet's:

- **Kinds declare their memory need** (`ramMiB`: inventory 128, cpu_bench 64, blob_verify 256,
  test_shard 2048, gpu_probe 512, qlora_probe 6144). It is a floor: a request or recommendation that
  states less is raised to it, more is kept.
- **Inventory reports pressure** (`ram.pressure` normal/high with reasons): available memory below
  max(1 GiB, 5 %) on every OS, plus committed memory >= 90 % of the limit (Windows), the kernel pressure
  level (macOS) or memory stall time (Linux PSI).
- **Placement** (`ramReserveMiB` per PC in the policy, default 2048): `INSUFFICIENT_RAM` when the job does
  not fit at all, `MEMORY_PRESSURE` when the PC reports pressure and the job is heavier than 128 MiB,
  `MEMORY_RESERVE` when the job would eat into the memory the PC keeps for its own services. Jobs already
  running on the PC count against what is left.
- **The PC checks again at start** (`fleet.min_available_mib`, default 1024; inventory always runs): below
  the floor nothing else starts (`LOCAL_MEMORY_HOLD`), under pressure only inventory and cpu_bench start
  (`LOCAL_MEMORY_PRESSURE`). The refusal happens before any work and reports the measurement, so the job
  is FAILED-not-started and can be requested again.
- **Fleet work runs below normal priority** (`fleet.low_priority`, default true; Windows
  BELOW_NORMAL_PRIORITY_CLASS, `nice 10` elsewhere), inherited by the test and probe child processes.
