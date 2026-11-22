# RIAN Commander — Health & Inspection module (MVP)

Status: MVP source + tests. Not deployed. No real e-mail is sent and no paid AI API is called.
Independent of the remote-execution agent (`eemf-operator/rian-v2-agent.py`): separate process,
separate credential kind, separate API, separate store. Nothing here can run a command on a device.

## Components

| Path | Role |
|---|---|
| `collector/rian_health_collector.py` | Read-only collector (Windows/macOS/Linux, Python 3.10+ stdlib). Disabled by default. HTTPS POST only, no listener, no command channel |
| `server/health-core.mjs` | Tenant directory (owner / collector principals), per-tenant keys (HKDF), sample validation, thresholds |
| `server/health-store.mjs` | SQLite store. Sample payloads, incident labels and outbox messages are AES-256-GCM encrypted with the tenant key |
| `server/health-alerts.mjs` | Pure rule evaluation + incident engine (open / ongoing / resolved, one notification per transition) |
| `server/health-notify.mjs` | E-mail composition, outbox, minimal SMTP (implicit TLS) transport, disabled unless the tenant enables it |
| `server/health-report.mjs` | Monthly facts, rule-based Korean summary, optional AI summary behind a fact guard |
| `server/health-pdf.mjs` | 1-page A4 PDF (no dependencies; Korean via the PDF standard CJK font HYGoThic-Medium) |
| `server/health-http.mjs` | `/v1/health/*` API handler (Fetch `Request` → `Response`) |
| `server/health-entry.mjs` | Service entry point (env configuration) |
| `tools/synthetic-30d.mjs` | Deterministic 30-day synthetic scenario (tenants A/B) for report validation |
| `tests/` | Node and Python tests, real-process E2E |

## Data collected (every 300 s by default)

online (server-side last receipt), CPU %, RAM total/used/%, disks total/used/free/%,
owner-listed processes/services running?, OS family/version/arch, collection ok + error codes.
No file contents, logs, user names, network data or credentials are collected.

## Credentials and isolation

- `owner` principal: reads its tenant's devices, metrics, incidents, reports.
- `collector` principal: bound to exactly one device; can only `POST /v1/health/ingest`.
  It cannot read anything, and the ingest response carries no instructions.
- Every query is tenant-scoped; another tenant's device/report answers `NOT_FOUND`.
- Tokens are stored as SHA-256 only. Tenant keys are derived from one master key with HKDF
  (`tenant|<id>`); a sample written for tenant A cannot be decrypted with tenant B's key.

## Rules (tenant-configurable defaults)

| Incident | Opens when | Resolves when |
|---|---|---|
| `CPU_HIGH` | ≥ 90 % in every sample for ≥ 10 min | latest sample < 90 % |
| `RAM_HIGH` | ≥ 90 % in every sample for ≥ 10 min | latest sample < 90 % |
| `DISK_LOW` (per mount) | ≥ 85 % used | < 85 % |
| `SERVICE_DOWN` (per name) | not running in 2 consecutive samples | running again |
| `OFFLINE` | no sample for ≥ 15 min | next sample |

An incident is notified once when it opens and once when it resolves; while it is ongoing only
its peak and last-seen time are updated. Rules never state a cause.

## Report (monthly, 1-page PDF + JSON)

period, devices and collection rate, CPU/RAM/disk avg/p95/max, incident history with open/resolve
times, summary, action items, and "unconfirmed / missing data" (always includes "cause not
confirmed" for incidents without cause evidence). Synthetic data is labelled on the page.

AI summary is optional and provider-neutral (`aiProvider.summarize(facts)`); its text is accepted
only if every percentage it cites exists in the facts and it states no cause that the facts do not
contain. Otherwise, or if the provider is unavailable, the rule-based summary is used.

## Retention candidates (not final policy)

raw samples 30 days, incidents/reports 12 months (`purge()`); final values depend on contracts.

## Verification (2026-11-22, Oui-MacStudio, macOS 26.7.3 arm64)

| Check | Result |
|---|---|
| Collector tests (Python 3.14.6 / 3.12.7) | 12/12 each: parsers for Linux/macOS/Windows outputs, config validation, live read-only sample, HTTPS-only transport, reply never executed, bounded queue + rate-limited logs |
| Server tests (Node 26) | 11/11: credentials and tenant isolation, validation, encryption at rest (no plaintext labels in the DB file), rules, 30-day synthetic ground truth, one notification per transition, SMTP once per event + bounded retries, report facts, AI guard, PDF structure, retention |
| Real-process E2E (loopback) | disabled collector sends nothing; real CPU/RAM/disk delivered; other tenant isolated; wrong token 401; server down handled; data survives restart |
| 30-day synthetic month | A: CPU 1, RAM 1, disk 1 (open), service 1, offline 1 — B: offline 1 — equals the scenario; a 5-minute spike and a single service miss raise nothing |
| Collector load | 0.515 CPU-s per collection = 0.17 % average at 300 s; 28.5 MB RSS (targets < 1 %, ≤ 60 MB) |
| Regression | existing V2 suites unchanged and passing (Node 67/67, Python 40/40) |

The PDF renders Korean correctly in macOS Quartz (checked visually). Other viewers rely on the
standard CJK font substitution and are not verified yet.

## Out of scope for the MVP

auto root-cause, auto-remediation, multiple channels, video/security devices, distributed
collection, billing, OS service installers for the collector.
