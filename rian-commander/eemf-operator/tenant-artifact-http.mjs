/** Opt-in HTTP adapter for staging. DO NOT mount on the legacy Relay without a durable store and deployment review. */
import { TenantDirectory, TenantArtifactBroker } from './tenant-artifact-core.mjs';

const MAX_BODY = 110_000; // one 64KiB base64 chunk + envelope
const headers = { 'cache-control':'no-store', 'content-type':'application/json; charset=utf-8', 'x-content-type-options':'nosniff' };
function respond(body, status=200) { return new Response(JSON.stringify(body), {status,headers}); }
function keysExact(data, expected) {
  return data && typeof data === 'object' && !Array.isArray(data) &&
    Object.keys(data).length === expected.length && expected.every(k=>Object.hasOwn(data,k));
}
async function jsonBody(request, expected) {
  if (request.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json') throw new Error('INVALID_BODY');
  const reader = request.body?.getReader();
  if (!reader) throw new Error('INVALID_BODY');
  const chunks=[]; let len=0;
  try {
    for(;;) {
      const {done,value} = await reader.read();
      if (done) break;
      len += value.byteLength;
      if (len>MAX_BODY) { await reader.cancel(); throw new Error('BODY_TOO_LARGE'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  let parsed;
  try { parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks))); } catch { throw new Error('INVALID_BODY'); }
  if (!keysExact(parsed, expected)) throw new Error('INVALID_BODY');
  return parsed;
}
/** No query-provided tenant identifier, device impersonation, or global admin fallback. */
export function createStagingArtifactHandler({directory, broker}) {
  if (!(directory instanceof TenantDirectory) || !(broker instanceof TenantArtifactBroker)) throw new Error('INVALID_HANDLER');
  return async request => {
    try {
      const url = new URL(request.url);
      if (url.search || url.hash || !url.pathname.startsWith('/v2/')) return respond({error:'NOT_FOUND'},404);
      const actor = directory.authenticate(request.headers.get('authorization'));
      const method = request.method.toUpperCase(), path=url.pathname;
      if (method === 'GET' && path === '/v2/tenant/devices') return respond({devices:directory.listOwnDevices(actor)});
      if (method === 'POST' && path === '/v2/transfers') {
        const body=await jsonBody(request,['sourceDeviceId','targetDeviceId','name','sizeBytes','sha256','approvalProof','idempotencyKey']);
        return respond(broker.begin({actor,...body}),201);
      }
      const part=/^\/v2\/transfers\/([0-9a-f-]{36})(?:\/(chunks\/([0-9]+)|finalize|ack|cancel))?$/.exec(path);
      if (!part) return respond({error:'NOT_FOUND'},404);
      const [,transferId,route,indexText]=part;
      if (!route && method==='GET') return respond(broker.status(actor,transferId));
      if (route==='finalize' && method==='POST') return respond(broker.finalize(actor,transferId));
      if (route==='ack' && method==='POST') {
        const body=await jsonBody(request,['receivedSha256']);
        return respond(broker.acknowledge({actor,transferId,...body}));
      }
      if (route==='cancel' && method==='POST') return respond(broker.cancel(actor,transferId));
      if (indexText !== undefined) {
        const index=Number(indexText);
        if (method==='PUT') {
          const body=await jsonBody(request,['base64','chunkSha256']);
          return respond(broker.upload({actor,transferId,index,...body}));
        }
        if (method==='GET') return respond(broker.download({actor,transferId,index}));
      }
      return respond({error:'NOT_FOUND'},404);
    } catch (e) {
      const code=e?.message || '';
      if (['ACCESS_DENIED','NOT_FOUND_OR_EXPIRED'].includes(code)) return respond({error:'NOT_FOUND'},404);
      if (code==='BODY_TOO_LARGE') return respond({error:'BODY_TOO_LARGE'},413);
      if (/CONFLICT|REPLAY|NOT_READY|NOT_WRITABLE|MISSING|MISMATCH|CANCEL|DISTINCT|EXPIRED/.test(code)) return respond({error:code},409);
      return respond({error:'INVALID_REQUEST'},400);
    }
  };
}
