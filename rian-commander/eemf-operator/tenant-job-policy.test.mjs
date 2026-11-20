import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {TenantDirectory} from './tenant-artifact-core.mjs';
import {OwnerJobApproval,TenantJobQueue,validateJobAction} from './tenant-job-policy.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const token=()=>randomBytes(40).toString('base64url');
function fixture() {
 const keys={oa:token(),ob:token(),aa:token(),ab:token()};
 const directory=new TenantDirectory({devices:[{id:'a1',tenantId:'tenantA'},{id:'b1',tenantId:'tenantB'}],principals:[
  {id:'oa',tenantId:'tenantA',kind:'owner',tokenSha256:sha(keys.oa)},
  {id:'ob',tenantId:'tenantB',kind:'owner',tokenSha256:sha(keys.ob)},
  {id:'aa',tenantId:'tenantA',kind:'agent',deviceId:'a1',tokenSha256:sha(keys.aa)},
  {id:'ab',tenantId:'tenantB',kind:'agent',deviceId:'b1',tokenSha256:sha(keys.ab)},
 ]});
 const actors=Object.fromEntries(Object.keys(keys).map(k=>[k,directory.authenticate('Bearer '+keys[k])]));
 const approval=new OwnerJobApproval(randomBytes(64).toString('hex'));
 let ms=1763600400000;
 const queue=new TenantJobQueue({directory,approval,clock:()=>ms});
 const consent=(owner,deviceId,action,args)=>approval.issue({tenantId:owner.tenantId,ownerId:owner.id,deviceId,action,argsSha256:sha(JSON.stringify(validateJobAction(action,args))),expiresAt:Math.floor(ms/1000)+60,nonce:randomBytes(16).toString('hex')});
 return {actors,queue,approval,consent,advance:seconds=>{ms+=seconds*1000}};
}

test('read-only jobs require tenant owner and are polled only by that tenant device',()=>{
 const x=fixture(),job=x.queue.enqueue({actor:x.actors.oa,deviceId:'a1',action:'status',args:{}});
 assert.equal(x.queue.get(x.actors.oa,job.jobId).state,'PENDING');
 assert.throws(()=>x.queue.get(x.actors.ob,job.jobId),/ACCESS_DENIED/);
 assert.throws(()=>x.queue.poll(x.actors.ab,'a1'),/ACCESS_DENIED/);
 assert.deepEqual(x.queue.poll(x.actors.ab,'b1'),{job:null});
 assert.equal(x.queue.poll(x.actors.aa,'a1').jobId,job.jobId);
});

test('rejects owner requests for another tenant device',()=>{
 const x=fixture();assert.throws(()=>x.queue.enqueue({actor:x.actors.oa,deviceId:'b1',action:'status',args:{}}),/ACCESS_DENIED/);
});

test('privileged actions require owner-signed exact operation, device, args and nonce',()=>{
 const x=fixture(),args={argv:['git','status'],cwd:'Documents',timeout:15};
 assert.throws(()=>x.queue.enqueue({actor:x.actors.oa,deviceId:'a1',action:'run_command',args}),/ACCESS_DENIED/);
 const proof=x.consent(x.actors.oa,'a1','run_command',args);
 assert.equal(x.queue.enqueue({actor:x.actors.oa,deviceId:'a1',action:'run_command',args,approvalProof:proof}).state,'PENDING');
 assert.throws(()=>x.queue.enqueue({actor:x.actors.oa,deviceId:'a1',action:'run_command',args,approvalProof:proof}),/APPROVAL_REPLAY/);
 const scoped=x.consent(x.actors.oa,'a1','run_command',args);
 assert.throws(()=>x.queue.enqueue({actor:x.actors.oa,deviceId:'a1',action:'run_command',args:{...args,timeout:16},approvalProof:scoped}),/ACCESS_DENIED/);
 assert.throws(()=>x.queue.enqueue({actor:x.actors.ob,deviceId:'b1',action:'run_command',args,approvalProof:scoped}),/ACCESS_DENIED/);
});

test('agent cannot impersonate owner or complete different tenant job',()=>{
 const x=fixture(),job=x.queue.enqueue({actor:x.actors.oa,deviceId:'a1',action:'status',args:{}});
 x.queue.poll(x.actors.aa,'a1');
 assert.throws(()=>x.queue.enqueue({actor:x.actors.aa,deviceId:'a1',action:'status',args:{}}),/ACCESS_DENIED/);
 assert.throws(()=>x.queue.complete(x.actors.ab,{jobId:job.jobId,result:{exitCode:0,output:'ok'}}),/ACCESS_DENIED/);
 assert.equal(x.queue.complete(x.actors.aa,{jobId:job.jobId,result:{exitCode:0,output:'ok'}}).state,'DONE');
 assert.equal(x.queue.get(x.actors.oa,job.jobId).result.output,'ok');
});

test('expired running lease fails closed; no duplicate auto retry',()=>{
 const x=fixture(),job=x.queue.enqueue({actor:x.actors.oa,deviceId:'a1',action:'status',args:{}});
 x.queue.poll(x.actors.aa,'a1');x.advance(121);x.queue.reap();
 assert.equal(x.queue.get(x.actors.oa,job.jobId).state,'UNKNOWN_DO_NOT_RETRY');
 assert.deepEqual(x.queue.poll(x.actors.aa,'a1'),{job:null});
 assert.throws(()=>x.queue.complete(x.actors.aa,{jobId:job.jobId,result:{exitCode:0,output:'late'}}),/JOB_NOT_RUNNING/);
});

test('owner can cancel pending work; result and job metadata stay tenant-scoped',()=>{
 const x=fixture(),job=x.queue.enqueue({actor:x.actors.oa,deviceId:'a1',action:'status',args:{}});
 assert.throws(()=>x.queue.cancel(x.actors.ob,job.jobId),/ACCESS_DENIED/);
 assert.equal(x.queue.cancel(x.actors.oa,job.jobId).state,'CANCELLED');
 assert.deepEqual(x.queue.poll(x.actors.aa,'a1'),{job:null});
});

test('rejects unknown fields, traversal, sensitive paths, code args with control characters',()=>{
 for(const path of ['../secrets.txt','AppData/foo','C:\\Users\\x','.ssh/id_rsa','a/.env','foo/.git/config'])
  assert.throws(()=>validateJobAction('read_file',{path}),/INVALID_PATH/);
 assert.throws(()=>validateJobAction('run_command',{argv:['git','status'],extra:true}),/INVALID_ARGS/);
 assert.throws(()=>validateJobAction('write_file',{path:'x',content:'ok',overwrite:'true'}),/INVALID_ARGS/);
 assert.throws(()=>validateJobAction('run_command',{argv:['powershell','-c','echo\nsecret']}),/INVALID_ARGS/);
 assert.throws(()=>validateJobAction('shell',{argv:['anything']}),/INVALID_ACTION/);
});

test('cancel after dispatch is reported as request, not proof that process stopped',()=>{
 const x=fixture(),job=x.queue.enqueue({actor:x.actors.oa,deviceId:'a1',action:'status',args:{}});
 x.queue.poll(x.actors.aa,'a1');
 assert.equal(x.queue.cancel(x.actors.oa,job.jobId).state,'CANCEL_REQUESTED');
 x.advance(121);x.queue.reap();
 assert.equal(x.queue.get(x.actors.oa,job.jobId).state,'UNKNOWN_DO_NOT_RETRY');
});

test('poll response arguments are detached from queued job and cancelled entries do not exhaust queue capacity',()=>{
 const x=fixture();
 const one=x.queue.enqueue({actor:x.actors.oa,deviceId:'a1',action:'read_file',args:{path:'Documents/report.txt'}});
 const got=x.queue.poll(x.actors.aa,'a1');
 got.args.path='Documents/mutated.txt';
 assert.equal(x.queue.get(x.actors.oa,one.jobId).action,'read_file');
 for(let i=0;i<3;i++){
   const j=x.queue.enqueue({actor:x.actors.oa,deviceId:'a1',action:'status',args:{}});
   x.queue.cancel(x.actors.oa,j.jobId);
 }
 assert.equal(x.queue.enqueue({actor:x.actors.oa,deviceId:'a1',action:'status',args:{}}).state,'PENDING');
});
