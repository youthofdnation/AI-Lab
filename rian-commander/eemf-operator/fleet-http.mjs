/**
 * Fleet tools on the V2 MCP endpoint (only when the queue has a FleetPolicy).
 *
 *  rian_v2_fleet_status     roster, online state, latest read-only inventory, active reservations
 *  rian_v2_fleet_recommend  where a job would go now, and why every other PC was skipped
 *  rian_v2_start_job        + device "auto" (placed by recommendation) and an optional `fleet`
 *                           {priority, cpu, ramMiB, vramMiB, dataClass}
 * There is still no approve tool: placing a job never skips the owner approval it needs.
 */
import {recommend} from './fleet-policy.mjs';

export function fleetToolDefs(queue) {
  if (!queue.fleet) return [];
  const req = {type: 'object', properties: {kind: {type: 'string'}, workUnits: {type: 'integer', minimum: 1}, placement: {type: 'string', enum: ['throughput', 'cores']}, cpu: {type: 'integer', minimum: 1, maximum: 256},
    ramMiB: {type: 'integer', minimum: 0}, vramMiB: {type: 'integer', minimum: 0}, dataClass: {type: 'string', enum: ['public', 'synthetic', 'private']}},
  required: ['kind'], additionalProperties: false};
  return [
    {name: 'rian_v2_request_inventory', description: 'Request a fixed read-only CPU/RAM/GPU and Windows GPU-engine process inventory for one registered PC. Returns job ID and browser approval URL unless an exact-scope grant already exists. No arbitrary commands, no files, no process termination.', inputSchema: {type:'object', properties:{device:{type:'string',minLength:1,maxLength:80},request_key:{type:'string',pattern:'^[A-Za-z0-9_-]{16,80}$'}},required:['device'],additionalProperties:false}},
    {name: 'rian_v2_fleet_status', description: 'RIAN AI Fleet: every pool PC with its status (ACTIVE / QUARANTINED), online state, the latest read-only inventory (CPU, RAM, GPU, disk, encryption, runtimes) and the jobs currently reserving it. Denylisted PCs never appear. Read only.',
      inputSchema: {type: 'object', properties: {}, additionalProperties: false}},
    {name: 'rian_v2_fleet_recommend', description: 'RIAN AI Fleet: rank the PCs that could take a job of this kind and size right now (fresh inventory minus reservations, concurrency, GPU slots, protected GPU processes, data class), with the reason each other PC was skipped. Starts nothing.',
      inputSchema: req},
  ];
}

function inventories(queue, actor) {
  const out = new Map();
  for (const id of queue.fleet.ids()) {
    const r = queue.latestSucceeded({actor, deviceId: id, kind: 'fleet.inventory'});
    if (r && r.result && r.result.ok) out.set(id, {captured: r.finished, snapshot: r.result.snapshot, job_id: r.job_id});
  }
  return out;
}

export function fleetRecommend(queue, actor, args, now) {
  const spec = queue.kinds.get(args.kind);
  const {placement, ...req} = args;
  if (req.ramMiB !== undefined && !Number.isInteger(req.ramMiB)) throw Error('INVALID_REQUIREMENTS');
  // The kind's own memory need is the floor, as at request time.
  const ramMiB = Math.max(spec.ramMiB || 0, req.ramMiB ?? 0) || undefined;
  return recommend(queue.fleet, {...req, ramMiB, needsGpu: spec.gpu === true}, inventories(queue, actor), queue.fleetActive(actor), now,
    {throughput: queue.fleetThroughput({actor, kind: args.kind}), placement: placement || null, maxOpenPerDevice: queue.limits.maxOpenPerDevice});
}

export function fleetStatus(queue, actor, now) {
  const inv = inventories(queue, actor), online = new Map(queue.devices(actor).map((d) => [d.device, d]));
  const active = queue.fleetActive(actor);
  const p = queue.fleet.summary();
  return {denylist_entries: p.denylistEntries, devices: p.devices.map((d) => {
    const i = inv.get(d.id), s = i && i.snapshot;
    return {...d, online: online.get(d.id)?.online === true, last_seen: online.get(d.id)?.last_seen || null,
      inventory: s ? {gpu_engines: s.gpu_engines ?? null, captured: i.captured, age_seconds: now - i.captured, host: s.host, os: s.os, cpu: s.cpu, ram: s.ram,
        gpus: s.gpus, disks: s.disks, encryption: s.encryption, runtimes: s.runtimes, ai_processes: s.ai_processes} : null,
      reservations: active.filter((a) => a.device === d.id)};
  })};
}

/** Returns undefined when `name` is not a fleet tool. */
export function callFleetTool(queue, actor, name, args, now, exact) {
  if (!queue.fleet) return undefined;
  if (name === 'rian_v2_fleet_status') { exact(args, []); return fleetStatus(queue, actor, now); }
  if (name === 'rian_v2_fleet_recommend') { exact(args, ['kind', 'cpu', 'ramMiB', 'vramMiB', 'dataClass', 'workUnits', 'placement'], ['kind']); return fleetRecommend(queue, actor, args, now); }
  return undefined;
}

/** device "auto": the best-ranked PC, or a FLEET_NO_ELIGIBLE_DEVICE error carrying the reasons. */
export function placeAuto(queue, actor, kind, fleet, now, params = null) {
  const f = fleet || {};
  const spec = queue.kinds.get(kind);
  const workUnits = typeof spec.workUnits === 'function' && params ? spec.workUnits(spec.validate(params)) : f.workUnits;
  const r = fleetRecommend(queue, actor, {kind, cpu: f.cpu, ramMiB: f.ramMiB, vramMiB: f.vramMiB, dataClass: f.dataClass, workUnits, placement: f.placement}, now);
  if (!r.candidates.length) throw Error('FLEET_NO_ELIGIBLE_DEVICE:' + r.excluded.map((e) => e.device + '=' + e.reason).join(',').slice(0, 300));
  return {device: r.candidates[0].device, placement: {mode: r.placement, chosen: r.candidates[0], alternatives: r.candidates.slice(1).map((c) => c.device), excluded: r.excluded}};
}
