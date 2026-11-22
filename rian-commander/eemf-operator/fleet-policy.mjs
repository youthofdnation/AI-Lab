/**
 * RIAN Commander V2 fleet policy: which PCs may take which work, and where a job should go.
 *
 * The policy is configuration, not code: device names, roles and the denylist come from
 * RIAN_STAGE_FLEET_POLICY_JSON on the central node and never from a request. It fails closed:
 *  - A policy without a non-empty denylist is refused (the owner requires a hard exclusion).
 *  - A denied host can never be registered, recommended, asked for a job or allowed to claim one,
 *    even if it is also listed as a device by mistake (that is a configuration error).
 *  - A QUARANTINED device only accepts the kinds in `quarantineKinds` (read-only inventory), so it
 *    can be checked without being given work.
 *  - Private data only goes to devices with `privateDataApproved: true` AND `private` in dataClasses.
 *  - A GPU job is not recommended to a device whose GPU runs a protected process (e.g. a production
 *    llama-server or another project's runner) - the existing occupant keeps its GPU.
 * Recommendation uses the latest read-only inventory result per device, minus the resources
 * reserved by that device's active jobs. Stale or missing inventory means "do not place here".
 */
export const DATA_CLASSES = Object.freeze(['public', 'synthetic', 'private']);
const STATUS = new Set(['ACTIVE', 'QUARANTINED']);
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const HOST = /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/;
const norm = (s) => String(s).trim().toLowerCase().replace(/\.local$/, '');

function int(v, lo, hi, code) {
  if (!Number.isInteger(v) || v < lo || v > hi) throw Error(code);
  return v;
}
function strList(v, re, code, {allowEmpty = false} = {}) {
  if (!Array.isArray(v) || (!allowEmpty && !v.length) || !v.every((x) => typeof x === 'string' && re.test(x))) throw Error(code);
  return [...new Set(v)];
}

export class FleetPolicy {
  #devices = new Map();
  #deniedHosts;
  #deniedIds;
  #quarantineKinds;
  constructor(raw, {knownKinds = null} = {}) {
    if (!raw || typeof raw !== 'object' || raw.version !== 1) throw Error('FLEET_POLICY_INVALID');
    const d = raw.denylist;
    if (!d || typeof d !== 'object') throw Error('FLEET_POLICY_DENYLIST_REQUIRED');
    const hosts = strList(d.hostnames || [], HOST, 'FLEET_POLICY_DENYLIST_INVALID', {allowEmpty: true});
    const ids = strList(d.deviceIds || [], ID, 'FLEET_POLICY_DENYLIST_INVALID', {allowEmpty: true});
    if (!hosts.length && !ids.length) throw Error('FLEET_POLICY_DENYLIST_REQUIRED');
    this.#deniedHosts = new Set(hosts.map(norm));
    this.#deniedIds = new Set(ids.map(norm));
    this.#quarantineKinds = new Set(strList(raw.quarantineKinds || ['fleet.inventory'], /^[a-z][a-z0-9_.]{0,63}$/, 'FLEET_POLICY_INVALID'));
    if (!Array.isArray(raw.devices) || !raw.devices.length || raw.devices.length > 32) throw Error('FLEET_POLICY_DEVICES_REQUIRED');
    for (const x of raw.devices) {
      if (!x || typeof x !== 'object' || !ID.test(x.id || '') || !HOST.test(x.hostname || '')) throw Error('FLEET_POLICY_DEVICE_INVALID');
      if (this.isDenied(x.id) || this.isDenied(x.hostname)) throw Error('FLEET_POLICY_DENIED_DEVICE_LISTED:' + x.id);
      if (this.#devices.has(x.id)) throw Error('FLEET_POLICY_DUPLICATE_DEVICE');
      if (!STATUS.has(x.status)) throw Error('FLEET_POLICY_DEVICE_INVALID');
      const kinds = strList(x.allowedKinds, /^[a-z][a-z0-9_.]{0,63}$/, 'FLEET_POLICY_DEVICE_INVALID');
      if (knownKinds && !kinds.every((k) => knownKinds.has(k))) throw Error('FLEET_POLICY_UNKNOWN_KIND:' + x.id);
      const dataClasses = strList(x.dataClasses, /^[a-z]+$/, 'FLEET_POLICY_DEVICE_INVALID');
      if (!dataClasses.every((c) => DATA_CLASSES.includes(c))) throw Error('FLEET_POLICY_DEVICE_INVALID');
      const privateOk = x.privateDataApproved === true;
      if (dataClasses.includes('private') && !privateOk) throw Error('FLEET_POLICY_PRIVATE_NOT_APPROVED:' + x.id);
      this.#devices.set(x.id, Object.freeze({
        id: x.id, hostname: x.hostname, role: typeof x.role === 'string' ? x.role.slice(0, 120) : '', status: x.status,
        maxConcurrent: int(x.maxConcurrent, 1, 16, 'FLEET_POLICY_DEVICE_INVALID'),
        gpuSlots: int(x.gpuSlots ?? 0, 0, 4, 'FLEET_POLICY_DEVICE_INVALID'),
        allowedKinds: Object.freeze(kinds), dataClasses: Object.freeze(dataClasses), privateDataApproved: privateOk,
        protectedGpuProcesses: Object.freeze(strList(x.protectedGpuProcesses || [], /^[A-Za-z0-9._-]{1,64}$/, 'FLEET_POLICY_DEVICE_INVALID', {allowEmpty: true}).map((p) => p.toLowerCase())),
        quarantineReason: x.status === 'QUARANTINED' ? String(x.quarantineReason || 'UNVERIFIED').slice(0, 200) : null,
      }));
    }
  }
  /** True for a denylisted device id or hostname (case-insensitive, ".local" ignored). */
  isDenied(name) {
    if (typeof name !== 'string' || !name) return false;
    const n = norm(name);
    return this.#deniedHosts.has(n) || this.#deniedIds.has(n);
  }
  ids() { return [...this.#devices.keys()]; }
  device(id) {
    if (this.isDenied(id)) throw Error('DEVICE_DENIED');
    const d = this.#devices.get(id);
    if (!d) throw Error('DEVICE_NOT_IN_FLEET');
    return d;
  }
  /** Map deviceId -> allowed kinds, for LongJobQueue's server-side allowlist. */
  deviceKinds() {
    return new Map([...this.#devices.values()].map((d) => [d.id, d.status === 'QUARANTINED'
      ? d.allowedKinds.filter((k) => this.#quarantineKinds.has(k)) : [...d.allowedKinds]]).filter(([, k]) => k.length));
  }
  concurrency() { return new Map([...this.#devices.values()].map((d) => [d.id, d.maxConcurrent])); }
  gpuSlots() { return new Map([...this.#devices.values()].map((d) => [d.id, d.gpuSlots])); }
  /** Throws a stable code when this device may not take this job; returns the device otherwise. */
  assertDispatchable(deviceId, kind, {needsGpu = false, dataClass = 'synthetic'} = {}) {
    const d = this.device(deviceId);
    if (!DATA_CLASSES.includes(dataClass)) throw Error('INVALID_DATA_CLASS');
    if (d.status === 'QUARANTINED' && !this.#quarantineKinds.has(kind)) throw Error('DEVICE_QUARANTINED');
    if (!d.allowedKinds.includes(kind)) throw Error('KIND_NOT_ALLOWED_FOR_DEVICE');
    if (!d.dataClasses.includes(dataClass) || (dataClass === 'private' && !d.privateDataApproved)) throw Error('DATA_CLASS_NOT_ALLOWED');
    if (needsGpu && d.gpuSlots < 1) throw Error('NO_GPU_SLOT');
    return d;
  }
  summary() {
    return {devices: [...this.#devices.values()].map((d) => ({id: d.id, role: d.role, status: d.status, maxConcurrent: d.maxConcurrent,
      gpuSlots: d.gpuSlots, allowedKinds: this.deviceKinds().get(d.id) || [], dataClasses: d.dataClasses,
      quarantineReason: d.quarantineReason})), denylistEntries: this.#deniedHosts.size + this.#deniedIds.size};
  }
}

/**
 * Rank devices for one job. `inventories`: Map deviceId -> {captured (unix s), snapshot}; `active`:
 * [{device, needsGpu, cpu, ramMiB, vramMiB}] reserved by not-yet-terminal jobs. Every excluded
 * device carries the first reason it failed, so the owner can see why work did not go there.
 */
export function recommend(policy, req, inventories, active, now, {maxAgeSeconds = 900} = {}) {
  const r = {kind: req.kind, needsGpu: req.needsGpu === true, cpu: req.cpu ?? 1, ramMiB: req.ramMiB ?? 256,
    vramMiB: req.vramMiB ?? 0, dataClass: req.dataClass ?? 'synthetic'};
  int(r.cpu, 1, 256, 'INVALID_REQUIREMENTS'); int(r.ramMiB, 0, 1 << 20, 'INVALID_REQUIREMENTS'); int(r.vramMiB, 0, 1 << 18, 'INVALID_REQUIREMENTS');
  const candidates = [], excluded = [];
  for (const id of policy.ids()) {
    let d;
    try { d = policy.assertDispatchable(id, r.kind, r); } catch (e) { excluded.push({device: id, reason: e.message}); continue; }
    const inv = inventories.get(id);
    if (!inv || !inv.snapshot) { excluded.push({device: id, reason: 'NO_INVENTORY'}); continue; }
    if (now - inv.captured > maxAgeSeconds) { excluded.push({device: id, reason: 'INVENTORY_STALE'}); continue; }
    const s = inv.snapshot, mine = active.filter((a) => a.device === id);
    if (mine.length >= d.maxConcurrent) { excluded.push({device: id, reason: 'CONCURRENCY_FULL'}); continue; }
    const cores = s.cpu?.logical || 0, load = Math.min(100, Math.max(0, s.cpu?.load_pct ?? 100));
    const freeCores = cores * (1 - load / 100) - mine.reduce((a, x) => a + (x.cpu || 1), 0);
    const freeRam = (s.ram?.available_mib || 0) - mine.reduce((a, x) => a + (x.ramMiB || 0), 0);
    if (freeCores < r.cpu - 0.25) { excluded.push({device: id, reason: 'INSUFFICIENT_CPU'}); continue; }
    if (freeRam < r.ramMiB) { excluded.push({device: id, reason: 'INSUFFICIENT_RAM'}); continue; }
    let freeVram = null;
    if (r.needsGpu) {
      const gpus = Array.isArray(s.gpus) ? s.gpus : [];
      if (!gpus.length) { excluded.push({device: id, reason: 'NO_GPU'}); continue; }
      if (mine.filter((x) => x.needsGpu).length >= d.gpuSlots) { excluded.push({device: id, reason: 'GPU_SLOT_FULL'}); continue; }
      const procs = gpus.flatMap((g) => (g.compute_processes || []).map((p) => String(p).toLowerCase()));
      if (d.protectedGpuProcesses.some((p) => procs.some((q) => q.includes(p)))) { excluded.push({device: id, reason: 'GPU_PROTECTED_PROCESS'}); continue; }
      const g = gpus[0];
      freeVram = (g.vram_total_mib || 0) - (g.vram_used_mib || 0) - mine.reduce((a, x) => a + (x.vramMiB || 0), 0);
      if (freeVram < r.vramMiB) { excluded.push({device: id, reason: 'INSUFFICIENT_VRAM'}); continue; }
    }
    // Headroom score: free cores weigh most for CPU work, free VRAM for GPU work.
    const score = Math.round((r.needsGpu ? freeVram / 1024 : 0) * 10 + freeCores * 5 + freeRam / 4096);
    candidates.push({device: id, score, free: {cores: Math.round(freeCores * 10) / 10, ram_mib: Math.round(freeRam), vram_mib: freeVram},
      running: mine.length, maxConcurrent: d.maxConcurrent});
  }
  candidates.sort((a, b) => b.score - a.score || a.device.localeCompare(b.device));
  return {requirements: r, candidates, excluded};
}

/**
 * GPU work must hand its memory back. The agent measures the GPU before the work and again after
 * the child process that did the work has exited; `release` = {before_mib, after_mib, leftover_pids}.
 */
export function verifyGpuRelease(output, {toleranceMiB = 256} = {}) {
  const rel = output && typeof output === 'object' ? output.gpu_release : null;
  if (!rel || !Number.isFinite(rel.before_mib) || !Number.isFinite(rel.after_mib)) return {state: 'NOT_REPORTED'};
  const leftover = Array.isArray(rel.leftover_pids) ? rel.leftover_pids.length : 0;
  const grew = rel.after_mib - rel.before_mib;
  return {state: leftover === 0 && grew <= toleranceMiB ? 'VERIFIED' : 'NOT_RETURNED', grew_mib: grew, leftover_processes: leftover};
}
