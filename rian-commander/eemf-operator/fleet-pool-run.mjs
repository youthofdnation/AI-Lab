/**
 * TEST-ONLY driver for a real multi-PC fleet run against a loopback V2 service on the central node.
 * Reads RUN_DIR/driver.json (0600: origin, owner token, approval password - synthetic test values).
 *
 *   node fleet-pool-run.mjs RUN_DIR call <tool> '<json args>' [--approve]
 *   node fleet-pool-run.mjs RUN_DIR bench <single:DEVICE|pool> <chunks> <units> [chunkOffset]
 *   node fleet-pool-run.mjs RUN_DIR wait <job_id> <seconds>
 *   node fleet-pool-run.mjs RUN_DIR audit <job_id>
 * Prints one JSON object. Never prints tokens or the password.
 */
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';

const [runDir, cmd, ...rest] = process.argv.slice(2);
const cfg = JSON.parse(readFileSync(join(runDir, 'driver.json'), 'utf8'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let rpc = 0;

async function tool(name, args) {
  const r = await fetch(cfg.origin + '/v2/mcp', {method: 'POST', headers: {'content-type': 'application/json', authorization: 'Bearer ' + cfg.ownerToken},
    body: JSON.stringify({jsonrpc: '2.0', id: ++rpc, method: 'tools/call', params: {name, arguments: args}})});
  const j = await r.json();
  const text = j.result?.content?.[0]?.text ?? '';
  if (j.result?.isError) return {error: text};
  return JSON.parse(text);
}
async function approve(url) {
  const html = await (await fetch(url)).text();
  const ticket = /name="ticket" value="([^"]+)"/.exec(html)?.[1];
  if (!ticket) return 'NO_TICKET';
  const r = await fetch(url, {method: 'POST', headers: {'content-type': 'application/x-www-form-urlencoded', origin: cfg.origin},
    body: new URLSearchParams({ticket, password: cfg.password})});
  return r.status === 200 ? 'APPROVED' : 'APPROVE_HTTP_' + r.status;
}
async function start(args) {
  const s = await tool('rian_v2_start_job', args);
  if (s.error) return s;
  if (s.approval_url) s.approval = await approve(s.approval_url);
  delete s.approval_url;
  return s;
}
async function wait(jobId, seconds) {
  const until = Date.now() + seconds * 1000;
  let s;
  do { s = await tool('rian_v2_job_status', {job_id: jobId, wait_seconds: 10}); } while (!s.terminal && !s.error && Date.now() < until);
  return s;
}

async function bench(mode, chunks, units, offset) {
  const t0 = Date.now(), pending = [], done = [], placementFails = [];
  const single = mode.startsWith('single:') ? mode.slice(7) : null;
  let next = 0;
  const limit = single ? cfg.maxConcurrent[single] : null;
  while (done.length < chunks) {
    // Feed: keep each PC at its own concurrency limit; the scheduler decides where in pool mode.
    while (next < chunks && (single ? pending.length < limit : true)) {
      const s = await start({device: single || 'auto', kind: 'fleet.cpu_bench', params: {chunk: offset + next, units}, fleet: {cpu: 1, ramMiB: 64}});
      if (s.error) { if (!single && /^FLEET_NO_ELIGIBLE_DEVICE/.test(s.error)) { placementFails.push(s.error.slice(0, 120)); break; } throw Error('START_' + s.error); }
      pending.push({job: s.job_id, device: s.device, chunk: offset + next, submitted: Date.now() - t0}); next++;
    }
    await sleep(1000);
    for (const p of [...pending]) {
      const s = await tool('rian_v2_job_status', {job_id: p.job});
      if (s.terminal) {
        pending.splice(pending.indexOf(p), 1);
        done.push({...p, state: s.state, finished: Date.now() - t0, seconds: s.result?.seconds ?? null, digest: s.result?.digest ?? null, host: s.result?.host ?? null});
      }
    }
  }
  const wall = (Date.now() - t0) / 1000;
  const byDevice = {};
  for (const d of done) byDevice[d.device] = (byDevice[d.device] || 0) + 1;
  return {mode, chunks, units, wall_seconds: wall, by_device: byDevice, all_succeeded: done.every((d) => d.state === 'SUCCEEDED'),
    placement_waits: placementFails.length, jobs: done.sort((a, b) => a.chunk - b.chunk)};
}

function audit(jobId) {
  const db = new DatabaseSync(cfg.dbPath, {readOnly: true});
  const rows = db.prepare('SELECT action,ts FROM audit WHERE object_id=? ORDER BY id').all(jobId);
  db.close();
  return {job_id: jobId, events: rows.map((r) => r.action), dispatched: rows.filter((r) => r.action === 'LONG_JOB_DISPATCHED').length};
}

let out;
if (cmd === 'call') {
  const args = JSON.parse(rest[1] || '{}');
  out = rest.includes('--approve') && rest[0] === 'rian_v2_start_job' ? await start(args) : await tool(rest[0], args);
} else if (cmd === 'bench') out = await bench(rest[0], Number(rest[1]), Number(rest[2]), Number(rest[3] || 0));
else if (cmd === 'wait') out = await wait(rest[0], Number(rest[1]));
else if (cmd === 'audit') out = audit(rest[0]);
else throw Error('USAGE');
console.log(JSON.stringify(out));
