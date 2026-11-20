import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import {TenantDirectory,OwnerTransferApproval,TenantArtifactBroker} from './tenant-artifact-core.mjs';
import {createStagingArtifactHandler} from './tenant-artifact-http.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');

function fixture() {
  const token=Object.fromEntries(['oA','sA','tA','oB','sB','tB'].map(k=>[k,randomBytes(40).toString('base64url')]));
  const principal=[['oA','A','owner'],['sA','A','agent','A1'],['tA','A','agent','A2'],['oB','B','owner'],['sB','B','agent','B1'],['tB','B','agent','B2']]
    .map(([id,tenantId,kind,deviceId])=>({id,tenantId,kind,...(deviceId?{deviceId}:{}),tokenSha256:hash(token[id])}));
  const directory=new TenantDirectory({principals:principal,devices:[{id:'A1',tenantId:'A'},{id:'A2',tenantId:'A'},{id:'B1',tenantId:'B'},{id:'B2',tenantId:'B'}]});
  const approval=new OwnerTransferApproval(randomBytes(48).toString('hex'));
  const at=1763600400000;
  const handler=createStagingArtifactHandler({directory,broker:new TenantArtifactBroker({directory,approval,clock:()=>at})});
  async function req(who,path,method='GET',data) {
    const request=new Request('https://staging.example'+path,{method,headers:{authorization:who?'Bearer '+token[who]:'',...(data?{'content-type':'application/json'}:{})},...(data?{body:JSON.stringify(data)}:{})});
    const result=await handler(request);return {status:result.status,json:await result.json()};
  }
  const bytes=Buffer.from('encrypted-by-source-example-in-future');
  const sha256=hash(bytes);
  const grant=(owner='oA',src='A1',dst='A2')=>approval.issue({tenantId:owner==='oA'?'A':'B',ownerId:owner,sourceDeviceId:src,targetDeviceId:dst,sizeBytes:bytes.length,
    sha256,expiresAt:Math.floor(at/1000)+120,nonce:randomBytes(16).toString('hex')});
  const create=async(owner='oA',src='A1',dst='A2')=>req(owner,'/v2/transfers','POST',{sourceDeviceId:src,targetDeviceId:dst,
    name:'output.bin',sizeBytes:bytes.length,sha256,approvalProof:grant(owner,src,dst),idempotencyKey:randomBytes(24).toString('base64url')});
  return {req,create,bytes,sha256};
}

test('HTTP denies unauthenticated calls without leaking fleet names',async()=>{
 const f=fixture();assert.deepEqual(await f.req(null,'/v2/tenant/devices'),{status:404,json:{error:'NOT_FOUND'}});
 assert.equal((await f.req('oA','/v2/tenant/devices')).json.devices.length,2);
 assert.deepEqual((await f.req('oB','/v2/tenant/devices')).json.devices,[{id:'B1'},{id:'B2'}]);
});

test('HTTP prevents cross-tenant reads, downloads, uploads and cancellation',async()=>{
 const f=fixture(),created=await f.create();assert.equal(created.status,201);
 const id=created.json.transferId;
 for(const [who,path,method,data] of [
  ['oB',"/v2/transfers/"+id,'GET',undefined],
  ['sB',"/v2/transfers/"+id+'/chunks/0','PUT',{base64:f.bytes.toString('base64'),chunkSha256:f.sha256}],
  ['tB',"/v2/transfers/"+id+'/chunks/0','GET',undefined],
  ['oB',"/v2/transfers/"+id+'/cancel','POST',undefined],
 ]) {const response=await f.req(who,path,method,data);assert.equal(response.status,404);}
});

test('HTTP transfers verified chunks from source to destination; denies same-tenant role confusion',async()=>{
 const f=fixture(),created=await f.create(),id=created.json.transferId,chunk=f.bytes.toString('base64');
 assert.equal((await f.req('tA',"/v2/transfers/"+id+'/chunks/0','PUT',{base64:chunk,chunkSha256:f.sha256})).status,404);
 assert.equal((await f.req('sA',"/v2/transfers/"+id+'/chunks/0','PUT',{base64:chunk,chunkSha256:f.sha256})).status,200);
 assert.equal((await f.req('sA',"/v2/transfers/"+id+'/finalize','POST')).json.state,'READY');
 assert.equal((await f.req('sA',"/v2/transfers/"+id+'/chunks/0')).status,404);
 const read=await f.req('tA',"/v2/transfers/"+id+'/chunks/0');
 assert.equal(Buffer.from(read.json.base64,'base64').toString(),f.bytes.toString());
 assert.equal((await f.req('tA',"/v2/transfers/"+id+'/ack','POST',{receivedSha256:f.sha256})).json.state,'DELIVERED');
});

test('HTTP rejects injected device claim, unknown fields, overlong request and invalid methods',async()=>{
 const f=fixture();
 assert.equal((await f.req('oA','/v2/transfers','POST',{device:'B1'})).status,400);
 assert.equal((await f.req('oA','/v2/transfers/../devices')).status,404);
 assert.equal((await f.req('oA','/v2/tenant/devices','POST')).status,404);
 assert.equal((await f.req('oA','/v2/transfers','POST',{blob:'x'.repeat(150_000)})).status,413);
});
