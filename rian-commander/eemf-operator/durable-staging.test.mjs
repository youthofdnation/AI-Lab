import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {TenantDirectory,OwnerTransferApproval,ARTIFACT_CHUNK_BYTES} from './tenant-artifact-core.mjs';
import {OwnerJobApproval,validateJobAction} from './tenant-job-policy.mjs';
import {StagingSqlite} from './staging-sqlite.mjs';
import {DurableTenantArtifactBroker} from './durable-tenant-artifacts.mjs';
import {DurableTenantJobQueue} from './durable-tenant-jobs.mjs';
import {createStagingArtifactHandler} from './tenant-artifact-http.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
function fixture(t) {
 const dir=mkdtempSync(join(tmpdir(),'rian-stage-')),file=join(dir,'state.db');
 const key=randomBytes(32).toString('hex'),tkn=Object.fromEntries(['oa','ob','sa','ta','sb','tb'].map(x=>[x,randomBytes(40).toString('base64url')]));
 const directory=new TenantDirectory({devices:[{id:'A1',tenantId:'A'},{id:'A2',tenantId:'A'},{id:'B1',tenantId:'B'},{id:'B2',tenantId:'B'}],
  principals:[['oa','A','owner'],['sa','A','agent','A1'],['ta','A','agent','A2'],['ob','B','owner'],['sb','B','agent','B1'],['tb','B','agent','B2']]
   .map(([id,tenantId,kind,deviceId])=>({id,tenantId,kind,...(deviceId?{deviceId}:{}),tokenSha256:sha(tkn[id])}))});
 const actors=Object.fromEntries(Object.keys(tkn).map(x=>[x,directory.authenticate('Bearer '+tkn[x])]));
 const approval=new OwnerTransferApproval(randomBytes(64).toString('hex'));
 const jobApproval=new OwnerJobApproval(randomBytes(64).toString('hex'));
 let timestamp=1763600400000;
 let store;
 function open(){
  store=new StagingSqlite({filename:file,encryptionKeyHex:key});
  return {store,broker:new DurableTenantArtifactBroker({directory,approval,store,clock:()=>timestamp}),jobs:new DurableTenantJobQueue({directory,approval:jobApproval,store,clock:()=>timestamp})};
 }
 function close(){if(store){store.close();store=null;}}
 t.after(()=>{close();rmSync(dir,{recursive:true,force:true})});
 function grant(bytes,tenant='A'){
  const sourceDeviceId=tenant+'1',targetDeviceId=tenant+'2',ownerId=tenant==='A'?'oa':'ob';
  return approval.issue({tenantId:tenant,ownerId,sourceDeviceId,targetDeviceId,sizeBytes:bytes.length,
   sha256:sha(bytes),expiresAt:Math.floor(timestamp/1000)+120,nonce:randomBytes(16).toString('hex')});
 }
 function begin(broker,bytes,tenant='A',keyString=randomBytes(24).toString('base64url')){
  return broker.begin({actor:actors[tenant==='A'?'oa':'ob'],sourceDeviceId:tenant+'1',targetDeviceId:tenant+'2',
   name:'result.bin',sizeBytes:bytes.length,sha256:sha(bytes),approvalProof:grant(bytes,tenant),idempotencyKey:keyString});
 }
 function upload(broker,actor,id,index,chunk){
  return broker.upload({actor,transferId:id,index,base64:chunk.toString('base64'),chunkSha256:sha(chunk)});
 }
 function permitJob(actor,device,action,args){
  return jobApproval.issue({tenantId:actor.tenantId,ownerId:actor.id,deviceId:device,action,
   argsSha256:sha(JSON.stringify(validateJobAction(action,args))),expiresAt:Math.floor(timestamp/1000)+120,nonce:randomBytes(16).toString('hex')});
 }
 return {open,close,file,key,actors,directory,approval,jobApproval,grant,begin,upload,permitJob,tkn,advance:n=>{timestamp+=n*1000;}};
}

test('encrypted partial chunks survive DB shutdown and restart; successful ack clears ciphertext',t=>{
 const f=fixture(t), first=f.open(), bytes=randomBytes(ARTIFACT_CHUNK_BYTES+23);
 const m=f.begin(first.broker,bytes), id=m.transferId;
 assert.equal(f.upload(first.broker,f.actors.sa,id,0,bytes.subarray(0,ARTIFACT_CHUNK_BYTES)).state,'STORED');
 f.close();
 const raw=readFileSync(f.file);
 assert.equal(raw.includes(bytes.subarray(0,32)),false,'AES ciphertext must not contain plaintext prefix');
 const second=f.open();
 assert.equal(second.broker.status(f.actors.oa,id).uploadedChunks,1);
 assert.equal(f.upload(second.broker,f.actors.sa,id,0,bytes.subarray(0,ARTIFACT_CHUNK_BYTES)).state,'ALREADY_PRESENT');
 f.upload(second.broker,f.actors.sa,id,1,bytes.subarray(ARTIFACT_CHUNK_BYTES));
 assert.equal(second.broker.finalize(f.actors.sa,id).state,'READY');
 const rebuilt=Buffer.concat([0,1].map(i=>Buffer.from(second.broker.download({actor:f.actors.ta,transferId:id,index:i}).base64,'base64')));
 assert.equal(sha(rebuilt),sha(bytes));
 assert.equal(second.broker.acknowledge({actor:f.actors.ta,transferId:id,receivedSha256:sha(rebuilt)}).state,'DELIVERED');
 f.close();
 const last=f.open();assert.equal(last.broker.status(f.actors.oa,id).state,'DELIVERED');
 assert.equal(last.broker.status(f.actors.oa,id).uploadedChunks,0);
});

test('two different tenants cannot read/download/modify other tenant durable transfer',t=>{
 const f=fixture(t),{broker}=f.open(),bytes=Buffer.from('client-A-sensitive-fixture-not-a-real-file');
 const m=f.begin(broker,bytes),id=m.transferId;
 assert.throws(()=>broker.status(f.actors.ob,id),/NOT_FOUND_OR_EXPIRED/);
 assert.throws(()=>broker.cancel(f.actors.ob,id),/NOT_FOUND_OR_EXPIRED/);
 assert.throws(()=>f.upload(broker,f.actors.sb,id,0,bytes),/ACCESS_DENIED/);
 assert.throws(()=>broker.download({actor:f.actors.tb,transferId:id,index:0}),/ACCESS_DENIED/);
 assert.throws(()=>broker.begin({actor:f.actors.ob,sourceDeviceId:'A1',targetDeviceId:'B2',name:'x',sizeBytes:1,sha256:sha('x'),approvalProof:'fake',idempotencyKey:'Q'.repeat(24)}),/ACCESS_DENIED/);
});

test('replay nonce and idempotency outcome survive restart',t=>{
 const f=fixture(t),bytes=Buffer.from('DURABLE_TEST'),grant=f.grant(bytes),keyString='K'.repeat(24);
 let {broker}=f.open();
 const input={actor:f.actors.oa,sourceDeviceId:'A1',targetDeviceId:'A2',name:'result.bin',sizeBytes:bytes.length,
  sha256:sha(bytes),approvalProof:grant,idempotencyKey:keyString};
 const created=broker.begin(input);f.close();
 broker=f.open().broker;
 assert.equal(broker.begin(input).transferId,created.transferId);
 assert.throws(()=>broker.begin({...input,idempotencyKey:'L'.repeat(24)}),/APPROVAL_REPLAY/);
 assert.throws(()=>broker.begin({...input,name:'different.bin'}),/IDEMPOTENCY_CONFLICT/);
});

test('encrypted job arguments/results persist; completed job is never sent twice',t=>{
 const f=fixture(t);let {jobs}=f.open(),args={argv:['git','status','--porcelain'],cwd:'Documents',timeout:15};
 const job=jobs.enqueue({actor:f.actors.oa,deviceId:'A1',action:'run_command',args,requestKey:'R'.repeat(24),approvalProof:f.permitJob(f.actors.oa,'A1','run_command',args)});
 const sent=jobs.poll(f.actors.sa,'A1');assert.equal(sent.jobId,job.jobId);
 const output='test-result-private-string-xyxyxy';
 assert.equal(jobs.complete(f.actors.sa,{jobId:job.jobId,result:{exitCode:0,output}}).state,'DONE');
 f.close();
 assert.equal(readFileSync(f.file).includes(Buffer.from(output)),false);
 ({jobs}=f.open());
 assert.equal(jobs.get(f.actors.oa,job.jobId).result.output,output);
 assert.deepEqual(jobs.poll(f.actors.sa,'A1'),{job:null});
 assert.equal(jobs.enqueue({actor:f.actors.oa,deviceId:'A1',action:'run_command',args,requestKey:'R'.repeat(24)}).jobId,job.jobId);
 assert.throws(()=>jobs.get(f.actors.ob,job.jobId),/JOB_NOT_FOUND/);
});

test('restart converts in-flight job to UNKNOWN_DO_NOT_RETRY even before lease expiry',t=>{
 const f=fixture(t);let {jobs}=f.open();
 const job=jobs.enqueue({actor:f.actors.oa,deviceId:'A1',action:'status',args:{},requestKey:'S'.repeat(24)});
 jobs.poll(f.actors.sa,'A1');f.close();
 ({jobs}=f.open());
 assert.equal(jobs.get(f.actors.oa,job.jobId).state,'UNKNOWN_DO_NOT_RETRY');
 assert.deepEqual(jobs.poll(f.actors.sa,'A1'),{job:null});
 assert.throws(()=>jobs.complete(f.actors.sa,{jobId:job.jobId,result:{exitCode:0,output:'late'}}),/JOB_NOT_RUNNING/);
});

test('pending jobs survive restart but expire safely without delivery',t=>{
 const f=fixture(t);let {jobs}=f.open();
 const job=jobs.enqueue({actor:f.actors.oa,deviceId:'A1',action:'status',args:{},requestKey:'P'.repeat(24)});
 f.close();({jobs}=f.open());
 assert.equal(jobs.get(f.actors.oa,job.jobId).state,'PENDING');
 f.advance(181);
 assert.deepEqual(jobs.poll(f.actors.sa,'A1'),{job:null});
 assert.equal(jobs.get(f.actors.oa,job.jobId).state,'EXPIRED');
});

test('wrong data encryption key cannot reopen existing database',t=>{
 const f=fixture(t);f.open();f.close();
 assert.throws(()=>new StagingSqlite({filename:f.file,encryptionKeyHex:randomBytes(32).toString('hex')}),/STORAGE_INTEGRITY_FAILED|STORAGE_KEY_MISMATCH/);
 assert.doesNotThrow(()=>f.open());
});

test('AES-GCM rejects database chunk tampering rather than serving damaged file',t=>{
 const f=fixture(t),{store,broker}=f.open(),bytes=Buffer.from('abc123');
 const id=f.begin(broker,bytes).transferId;
 f.upload(broker,f.actors.sa,id,0,bytes);
 store.db.prepare('UPDATE transfer_chunks SET cipher=? WHERE transfer_id=? AND idx=0').run(Buffer.alloc(bytes.length,0),id);
 assert.throws(()=>broker.finalize(f.actors.sa,id),/STORAGE_INTEGRITY_FAILED/);
});

test('staging HTTP handler interoperates with durable broker after restart',async t=>{
 const f=fixture(t);let {broker}=f.open();const bytes=Buffer.from('hello');
 const m=f.begin(broker,bytes),id=m.transferId;f.close();
 ({broker}=f.open());
 const handler=createStagingArtifactHandler({directory:f.directory,broker});
 const request=new Request('https://internal.test/v2/transfers/'+id,{headers:{authorization:'Bearer '+f.tkn.oa}});
 const response=await handler(request);
 assert.equal(response.status,200);assert.equal((await response.json()).transferId,id);
 const denied=await handler(new Request('https://internal.test/v2/transfers/'+id,{headers:{authorization:'Bearer '+f.tkn.ob}}));
 assert.equal(denied.status,404);
});

test('tenant quota bounds active storage size before accepting new transfer',t=>{
 const f=fixture(t),{broker}=f.open();
 const bytes=Buffer.alloc(8*1024*1024);
 for(let i=0;i<4;i++)f.begin(broker,bytes);
 assert.throws(()=>f.begin(broker,bytes),/TENANT_QUOTA_EXCEEDED/);
});

test('audit records only IDs/action types, not job args, file contents or bearer tokens',t=>{
 const f=fixture(t),{store,broker,jobs}=f.open();
 const bytes=Buffer.from('very-private-fixture-string');
 const id=f.begin(broker,bytes).transferId;
 f.upload(broker,f.actors.sa,id,0,bytes);
 jobs.enqueue({actor:f.actors.oa,deviceId:'A1',action:'read_file',args:{path:'Documents/private-path.txt'},requestKey:'Z'.repeat(24)});
 const rows=store.db.prepare('SELECT tenant,actor,action FROM audit ORDER BY id').all();
 assert(rows.length>=2);assert(rows.every(x=>!JSON.stringify(x).includes('private')&&!JSON.stringify(x).includes(f.tkn.oa)));
});
