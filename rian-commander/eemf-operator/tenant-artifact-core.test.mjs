import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import {
  TenantDirectory, OwnerTransferApproval, TenantArtifactBroker,
  ARTIFACT_CHUNK_BYTES, ARTIFACT_MAX_BYTES, ARTIFACT_TTL_SECONDS,
} from './tenant-artifact-core.mjs';

const hash = buf => createHash('sha256').update(buf).digest('hex');
const token = () => randomBytes(40).toString('base64url');
function setup() {
  const keys = Object.fromEntries(['ownerA','sourceA','targetA','ownerB','sourceB','targetB'].map(k => [k,token()]));
  const principals = [
    ['ownerA','tenant-A','owner',null],['sourceA','tenant-A','agent','pc-A-1'],['targetA','tenant-A','agent','pc-A-2'],
    ['ownerB','tenant-B','owner',null],['sourceB','tenant-B','agent','pc-B-1'],['targetB','tenant-B','agent','pc-B-2'],
  ].map(([id, tenantId, kind, deviceId])=>({id, tenantId,kind, ...(deviceId?{deviceId}:{}),tokenSha256:hash(keys[id])}));
  const directory = new TenantDirectory({principals,devices:[
    {id:'pc-A-1',tenantId:'tenant-A'},{id:'pc-A-2',tenantId:'tenant-A'},
    {id:'pc-B-1',tenantId:'tenant-B'},{id:'pc-B-2',tenantId:'tenant-B'},
  ]});
  const actor = Object.fromEntries(Object.keys(keys).map(k=>[k,directory.authenticate('Bearer '+keys[k])]));
  const approval = new OwnerTransferApproval(randomBytes(64).toString('hex'));
  let clockMs = 1763600400000;
  const broker = new TenantArtifactBroker({directory,approval,clock:()=>clockMs});
  function begin(data=Buffer.from('a small CCTV result artifact'), opts={}) {
    const owner = opts.owner || actor.ownerA;
    const sourceDeviceId = opts.sourceDeviceId || 'pc-A-1';
    const targetDeviceId = opts.targetDeviceId || 'pc-A-2';
    const name = opts.name || '결과.zip';
    const sha256 = hash(data);
    const claim = {tenantId:owner.tenantId,ownerId:owner.id,sourceDeviceId,targetDeviceId,
      sizeBytes:data.length,sha256,expiresAt:Math.floor(clockMs/1000)+120,nonce:randomBytes(16).toString('hex')};
    const approvalProof = opts.approvalProof || approval.issue(claim);
    const input = {actor:owner,sourceDeviceId,targetDeviceId,name,sizeBytes:data.length,sha256,
      approvalProof,idempotencyKey:opts.idempotencyKey||randomBytes(24).toString('base64url')};
    return {manifest:broker.begin(input),data,input,claim};
  }
  function uploadAll({manifest,data}, from=actor.sourceA) {
    for(let index=0;index<Math.ceil(data.length/ARTIFACT_CHUNK_BYTES);index++){
      const chunk=data.subarray(index*ARTIFACT_CHUNK_BYTES,(index+1)*ARTIFACT_CHUNK_BYTES);
      broker.upload({actor:from,transferId:manifest.transferId,index,base64:chunk.toString('base64'),chunkSha256:hash(chunk)});
    }
  }
  return {directory,actor,approval,broker,keys,begin,uploadAll,setTime:n=>{clockMs=n},getTime:()=>clockMs};
}

test('auth is bearer-token bound; forged actors, unknown and malformed tokens are denied',()=>{
  const {directory,actor,keys}=setup();
  assert.deepEqual(directory.listOwnDevices(actor.ownerA).map(x=>x.id),['pc-A-1','pc-A-2']);
  assert.deepEqual(directory.listOwnDevices(actor.ownerB).map(x=>x.id),['pc-B-1','pc-B-2']);
  assert.throws(()=>directory.authenticate('Bearer invalid'),/ACCESS_DENIED/);
  assert.throws(()=>directory.authenticate('Basic '+keys.ownerA),/ACCESS_DENIED/);
  assert.throws(()=>directory.listOwnDevices({...actor.ownerA}),/ACCESS_DENIED/);
  assert.throws(()=>directory.listOwnDevices(actor.sourceA),/ACCESS_DENIED/);
});

test('rejects duplicate device ownership and cross-tenant agent binding',()=>{
  const sha=hash('test'.repeat(12));
  const base={devices:[{id:'pc1',tenantId:'a'}],principals:[{id:'agent',tenantId:'b',kind:'agent',deviceId:'pc1',tokenSha256:sha}]};
  assert.throws(()=>new TenantDirectory(base),/INVALID_PRINCIPAL_DEVICE/);
  assert.throws(()=>new TenantDirectory({...base,devices:[...base.devices,...base.devices]}),/DUPLICATE_DEVICE/);
});

test('tenant B cannot create a transfer involving tenant A device',()=>{
  const x=setup();
  assert.throws(()=>x.begin(Buffer.from('demo'),{owner:x.actor.ownerB,sourceDeviceId:'pc-A-1',targetDeviceId:'pc-B-2'}),/ACCESS_DENIED/);
});

test('requires exact valid owner-signed grant; rejects forged, mismatched, expired and reused grants',()=>{
  const x=setup();
  const data=Buffer.from('valid');
  const claim={tenantId:'tenant-A',ownerId:'ownerA',sourceDeviceId:'pc-A-1',targetDeviceId:'pc-A-2',
    sizeBytes:data.length,sha256:hash(data),expiresAt:Math.floor(x.getTime()/1000)+60,nonce:randomBytes(16).toString('hex')};
  const proof=x.approval.issue(claim);
  const {manifest}=x.begin(data,{approvalProof:proof});
  assert.equal(manifest.state,'UPLOADING');
  assert.throws(()=>x.begin(data,{approvalProof:proof}),/APPROVAL_REPLAY/);
  assert.throws(()=>x.begin(data,{approvalProof:proof.slice(0,-1)+'0'}),/ACCESS_DENIED|APPROVAL_REPLAY/);
  const other={...claim,nonce:randomBytes(16).toString('hex')};
  assert.throws(()=>x.begin(Buffer.from('different'),{approvalProof:x.approval.issue(other)}),/ACCESS_DENIED/);
  const expired={...claim,expiresAt:Math.floor(x.getTime()/1000)-10,nonce:randomBytes(16).toString('hex')};
  assert.throws(()=>x.begin(data,{approvalProof:x.approval.issue(expired)}),/ACCESS_DENIED/);
});

test('prevents guessed transfer IDs and tenant cross-access to status, upload, download, cancel',()=>{
  const x=setup(), t=x.begin();
  assert.throws(()=>x.broker.status(x.actor.ownerB,t.manifest.transferId),/ACCESS_DENIED/);
  assert.throws(()=>x.broker.status(x.actor.sourceB,t.manifest.transferId),/ACCESS_DENIED/);
  assert.throws(()=>x.broker.cancel(x.actor.ownerB,t.manifest.transferId),/ACCESS_DENIED/);
  assert.throws(()=>x.broker.upload({actor:x.actor.sourceB,transferId:t.manifest.transferId,index:0,base64:t.data.toString('base64'),chunkSha256:hash(t.data)}),/ACCESS_DENIED/);
  assert.throws(()=>x.broker.download({actor:x.actor.targetB,transferId:t.manifest.transferId,index:0}),/ACCESS_DENIED/);
  assert.throws(()=>x.broker.status(x.actor.ownerA,'guess'),/NOT_FOUND_OR_EXPIRED/);
});

test('same-tenant wrong agent cannot upload or download another device transfer',()=>{
  const x=setup(), t=x.begin();
  assert.throws(()=>x.broker.upload({actor:x.actor.targetA,transferId:t.manifest.transferId,index:0,base64:t.data.toString('base64'),chunkSha256:hash(t.data)}),/ACCESS_DENIED/);
  assert.throws(()=>x.broker.download({actor:x.actor.sourceA,transferId:t.manifest.transferId,index:0}),/ACCESS_DENIED/);
});

test('chunk integrity, exact size, idempotent retry, and conflicting replay rejection',()=>{
  const x=setup(), t=x.begin(), id=t.manifest.transferId;
  const request={actor:x.actor.sourceA,transferId:id,index:0,base64:t.data.toString('base64'),chunkSha256:hash(t.data)};
  assert.throws(()=>x.broker.upload({...request,chunkSha256:'a'.repeat(64)}),/CHUNK_HASH_OR_LENGTH_MISMATCH/);
  assert.throws(()=>x.broker.upload({...request,base64:'####'}),/CHUNK_HASH_OR_LENGTH_MISMATCH/);
  assert.deepEqual(x.broker.upload(request),{state:'STORED',index:0});
  assert.deepEqual(x.broker.upload(request),{state:'ALREADY_PRESENT',index:0});
  assert.throws(()=>x.broker.upload({...request,base64:Buffer.from('altered').toString('base64'),chunkSha256:hash('altered')}),/CHUNK_HASH_OR_LENGTH_MISMATCH|CHUNK_REPLAY_CONFLICT/);
});

test('two-chunk transfer resumes at missing chunk, verifies global hash, is downloaded by target and acknowledged',()=>{
  const x=setup(), bytes=randomBytes(ARTIFACT_CHUNK_BYTES+11), t=x.begin(bytes), id=t.manifest.transferId;
  assert.equal(t.manifest.totalChunks,2);
  const chunk0=bytes.subarray(0,ARTIFACT_CHUNK_BYTES);
  x.broker.upload({actor:x.actor.sourceA,transferId:id,index:0,base64:chunk0.toString('base64'),chunkSha256:hash(chunk0)});
  assert.equal(x.broker.status(x.actor.ownerA,id).uploadedChunks,1);
  assert.throws(()=>x.broker.finalize(x.actor.sourceA,id),/CHUNKS_MISSING/);
  assert.throws(()=>x.broker.download({actor:x.actor.targetA,transferId:id,index:0}),/TRANSFER_NOT_READY/);
  x.uploadAll(t);
  assert.equal(x.broker.finalize(x.actor.sourceA,id).state,'READY');
  const received=Buffer.concat([0,1].map(index=>Buffer.from(x.broker.download({actor:x.actor.targetA,transferId:id,index}).base64,'base64')));
  assert.equal(hash(received),hash(bytes));
  assert.throws(()=>x.broker.acknowledge({actor:x.actor.targetA,transferId:id,receivedSha256:'0'.repeat(64)}),/DESTINATION_HASH_MISMATCH/);
  assert.equal(x.broker.acknowledge({actor:x.actor.targetA,transferId:id,receivedSha256:hash(received)}).state,'DELIVERED');
  assert.equal(x.broker.acknowledge({actor:x.actor.targetA,transferId:id,receivedSha256:hash(received)}).uploadedChunks,0);
  assert.throws(()=>x.broker.download({actor:x.actor.targetA,transferId:id,index:0}),/TRANSFER_NOT_READY/);
});

test('valid per-chunk hashes do not bypass declared whole-file checksum',()=>{
  const x=setup(), t=x.begin(Buffer.from('ABCD'));
  x.broker.upload({actor:x.actor.sourceA,transferId:t.manifest.transferId,index:0,base64:Buffer.from('WXYZ').toString('base64'),chunkSha256:hash('WXYZ')});
  assert.throws(()=>x.broker.finalize(x.actor.sourceA,t.manifest.transferId),/FULL_HASH_MISMATCH/);
  assert.equal(x.broker.status(x.actor.ownerA,t.manifest.transferId).state,'FAILED_INTEGRITY');
});

test('owner-only cancellation invalidates subsequent source and target operations',()=>{
  const x=setup(), t=x.begin();
  assert.throws(()=>x.broker.cancel(x.actor.sourceA,t.manifest.transferId),/ACCESS_DENIED/);
  assert.equal(x.broker.cancel(x.actor.ownerA,t.manifest.transferId).state,'CANCELLED');
  assert.throws(()=>x.broker.upload({actor:x.actor.sourceA,transferId:t.manifest.transferId,index:0,base64:t.data.toString('base64'),chunkSha256:hash(t.data)}),/TRANSFER_NOT_WRITABLE/);
});

test('idempotency key returns same transfer only for same owner, tenant and manifest',()=>{
  const x=setup(), key=randomBytes(24).toString('base64url'), t=x.begin(Buffer.from('DEMO'),{idempotencyKey:key});
  const retry=x.broker.begin(t.input);
  assert.equal(retry.transferId,t.manifest.transferId);
  assert.throws(()=>x.broker.begin({...t.input,name:'changed.txt'}),/IDEMPOTENCY_CONFLICT/);
});

test('expiry and sweep discard artifact chunks; authorization cannot revive expired transfer',()=>{
  const x=setup(), t=x.begin(); x.uploadAll(t);
  x.setTime(x.getTime() + (ARTIFACT_TTL_SECONDS+1)*1000);
  assert.throws(()=>x.broker.status(x.actor.ownerA,t.manifest.transferId),/NOT_FOUND_OR_EXPIRED/);
  x.broker.sweep();
  assert.throws(()=>x.broker.begin(t.input),/ACCESS_DENIED/);
});

test('rejects path traversal names, overlarge size, invalid IDs, same-device transfer and fake principal',()=>{
  const x=setup();
  assert.throws(()=>x.begin(Buffer.from('abc'),{name:'../../secrets.txt'}),/INVALID_ARTIFACT_NAME/);
  assert.throws(()=>x.begin(Buffer.from('abc'),{sourceDeviceId:'pc-A-1',targetDeviceId:'pc-A-1'}),/DISTINCT_DEVICES_REQUIRED/);
  assert.throws(()=>x.begin(Buffer.from('abc'),{sourceDeviceId:'pc-A-1',targetDeviceId:'pc-B-2'}),/ACCESS_DENIED/);
  assert.throws(()=>x.begin(Buffer.alloc(ARTIFACT_MAX_BYTES+1)),/INVALID_MANIFEST|INVALID_GRANT/);
  assert.throws(()=>x.broker.begin({...x.begin().input,actor:{...x.actor.ownerA}}),/ACCESS_DENIED/);
});
