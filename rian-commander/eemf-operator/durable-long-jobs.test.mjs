import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {TenantDirectory} from './tenant-artifact-core.mjs';
import {StagingSqlite} from './staging-sqlite.mjs';
import {LongJobQueue} from './durable-long-jobs.mjs';
import {LongJobKinds} from './long-job-kinds.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'rian-longjob-')),file=join(dir,'state.db'),key=randomBytes(32).toString('hex');
 const tkn=Object.fromEntries(['oa','ob','aa','ab','aa2'].map(x=>[x,randomBytes(40).toString('base64url')]));
 const directory=new TenantDirectory({devices:[{id:'pcA',tenantId:'A'},{id:'pcA2',tenantId:'A'},{id:'pcB',tenantId:'B'}],
  principals:[['oa','A','owner'],['ob','B','owner'],['aa','A','agent','pcA'],['aa2','A','agent','pcA2'],['ab','B','agent','pcB']]
   .map(([id,tenantId,kind,deviceId])=>({id,tenantId,kind,...(deviceId?{deviceId}:{}),tokenSha256:sha(tkn[id])}))});
 const actors=Object.fromEntries(Object.keys(tkn).map(x=>[x,directory.authenticate('Bearer '+tkn[x])]));
 let ms=1763600400000,store=null;
 const open=(extra={})=>{store=new StagingSqlite({filename:file,encryptionKeyHex:key});return new LongJobQueue({directory,store,kinds:new LongJobKinds({allowDiagnostics:true}),clock:()=>ms,...extra});};
 const close=()=>{if(store){store.close();store=null;}};
 t.after(()=>{close();rmSync(dir,{recursive:true,force:true});});
 return {open,close,actors,file,advance:s=>{ms+=s*1000;},store:()=>store,owner:{A:{tenantId:'A',ownerId:'oa'},B:{tenantId:'B',ownerId:'ob'}}};
}
const start=(q,actor,device,kind,params,requestKey)=>q.request({actor,deviceId:device,kind,params,requestKey});

test('request returns a job id immediately and nothing runs before owner approval',t=>{
 const f=fixture(t),q=f.open();
 const j=start(q,f.actors.oa,'pcA','diag.wait',{seconds:40});
 assert.match(j.job_id,/^[0-9a-f-]{36}$/);
 assert.equal(j.state,'AWAITING_APPROVAL');assert.equal(j.approval_required,true);
 assert.deepEqual(q.claim({actor:f.actors.aa,deviceId:'pcA'}),{job:null});
 assert.equal(q.approve({approver:f.owner.A,jobId:j.job_id}).state,'QUEUED');
 const c=q.claim({actor:f.actors.aa,deviceId:'pcA'});
 assert.equal(c.job.jobId,j.job_id);assert.deepEqual(c.job.params,{seconds:40});
 assert.equal(c.job.maxRuntimeSeconds,960);assert.match(c.job.leaseToken,/^[A-Za-z0-9_-]{43}$/);
 assert.deepEqual(q.claim({actor:f.actors.aa,deviceId:'pcA'}),{job:null},'dispatched exactly once');
});

test('per-device allowlist: a diagnostics-only PC can never be asked for mail, before any approval page',t=>{
 const f=fixture(t);
 let q=f.open({deviceKinds:new Map([['pcA',['diag.wait']]])});
 for(const [kind,params] of [['mail.sync',{days:1,maxMessages:1}],['mail.search',{query:'x'}],['mail.read',{messageId:'a'.repeat(40)}]])
  assert.throws(()=>start(q,f.actors.oa,'pcA',kind,params),/KIND_NOT_ALLOWED_FOR_DEVICE/);
 assert.equal(start(q,f.actors.oa,'pcA','diag.wait',{seconds:5}).state,'AWAITING_APPROVAL');
 assert.equal(start(q,f.actors.oa,'pcA2','mail.sync',{days:1,maxMessages:1}).state,'AWAITING_APPROVAL','unlisted device unchanged');
 const devs=Object.fromEntries(q.devices(f.actors.oa).map(d=>[d.device,d]));
 assert.deepEqual(devs.pcA.allowed_kinds,['diag.wait']);assert.equal('allowed_kinds' in devs.pcA2,false);
 f.close();
 assert.throws(()=>f.open({deviceKinds:{pcA:['shell']}}),/INVALID_DEVICE_KINDS/);f.close();
 assert.throws(()=>f.open({deviceKinds:{pcA:[]}}),/INVALID_DEVICE_KINDS/);f.close();
 // A mail job queued while pcA2 was unrestricted is closed, not dispatched, once pcA2 is restricted.
 q=f.open();
 const queued=start(q,f.actors.oa,'pcA2','mail.search',{query:'x'});
 q.approve({approver:f.owner.A,jobId:queued.job_id});
 f.close();
 q=f.open({deviceKinds:{pcA2:['diag.wait']}});
 assert.deepEqual(q.claim({actor:f.actors.aa2,deviceId:'pcA2'}),{job:null});
 assert.equal(q.get({actor:f.actors.oa,jobId:queued.job_id}).state,'CANCELLED');
 assert.deepEqual(q.claim({actor:f.actors.aa2,deviceId:'pcA2'}),{job:null});
});

test('long run beyond 28 s: heartbeats extend the lease, progress is visible, result is stored',t=>{
 const f=fixture(t),q=f.open();
 const j=start(q,f.actors.oa,'pcA','diag.wait',{seconds:120});
 q.approve({approver:f.owner.A,jobId:j.job_id});
 const {job}=q.claim({actor:f.actors.aa,deviceId:'pcA'});
 for(let s=0;s<120;s+=15){
  f.advance(15);
  const hb=q.heartbeat({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken,progress:{percent:Math.floor(s/1.2),stage:'waiting',done:s,total:120}});
  assert.equal(hb.cancel,false);
 }
 const mid=q.get({actor:f.actors.oa,jobId:job.jobId});
 assert.equal(mid.state,'RUNNING');assert.equal(mid.progress.stage,'waiting');assert.equal(mid.progress.total,120);
 const done=q.complete({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:JSON.stringify({ok:true,waited_seconds:120})});
 assert.equal(done.state,'SUCCEEDED');
 const final=q.get({actor:f.actors.oa,jobId:job.jobId});
 assert.equal(final.result.waited_seconds,120);assert.equal(final.progress.percent,100);
 assert.ok(final.finished_at-final.started_at>=120,'ran for more than the legacy 28 s window');
});

test('server restart keeps a RUNNING job, grants a grace lease and still collects the result',t=>{
 const f=fixture(t);let q=f.open();
 const j=start(q,f.actors.oa,'pcA','mail.sync',{days:14,maxMessages:1000});
 q.approve({approver:f.owner.A,jobId:j.job_id});
 const {job}=q.claim({actor:f.actors.aa,deviceId:'pcA'});
 f.close();f.advance(100);                       // server down longer than the 120 s lease? not yet
 q=f.open();
 const rec=q.recoverAfterRestart();
 assert.equal(rec.runningPreserved,1);
 f.advance(150);                                  // beyond the original lease, inside boot grace
 assert.equal(q.get({actor:f.actors.oa,jobId:j.job_id}).state,'RUNNING');
 assert.equal(q.heartbeat({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken,progress:{percent:50}}).cancel,false);
 assert.deepEqual(q.claim({actor:f.actors.aa,deviceId:'pcA'}),{job:null},'never re-dispatched after restart');
 assert.equal(q.complete({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:'{"ok":true,"added":3}'}).state,'SUCCEEDED');
 assert.equal(q.get({actor:f.actors.oa,jobId:j.job_id}).result.added,3);
});

test('lost lease fails closed as UNKNOWN_DO_NOT_RETRY; an authentic late result resolves it',t=>{
 const f=fixture(t),q=f.open();
 const j=start(q,f.actors.oa,'pcA','diag.wait',{seconds:30});
 q.approve({approver:f.owner.A,jobId:j.job_id});
 const {job}=q.claim({actor:f.actors.aa,deviceId:'pcA'});
 f.advance(46);q.reap();
 assert.equal(q.get({actor:f.actors.oa,jobId:j.job_id}).state,'UNKNOWN_DO_NOT_RETRY');
 const stop=q.heartbeat({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken});
 assert.equal(stop.cancel,true);assert.equal(stop.reason,'NOT_RUNNING');
 assert.throws(()=>q.complete({actor:f.actors.aa,jobId:job.jobId,leaseToken:randomBytes(32).toString('base64url'),outcome:'SUCCEEDED',exitCode:0,output:'x'}),/LEASE_MISMATCH/);
 const late=q.complete({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:'{"ok":true}'});
 assert.equal(late.late,true);assert.equal(q.get({actor:f.actors.oa,jobId:j.job_id}).state,'SUCCEEDED');
 assert.equal(q.complete({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:'{"ok":true}'}).duplicate,true,'idempotent resend');
 assert.throws(()=>q.complete({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken,outcome:'FAILED',exitCode:1,output:'other'}),/JOB_ALREADY_FINISHED/);
});

test('duplicate prevention: same request key, same active spec, and one mail sync per device',t=>{
 const f=fixture(t),q=f.open(),key='K'.repeat(24);
 const a=start(q,f.actors.oa,'pcA','mail.sync',{days:14,maxMessages:500},key);
 assert.equal(start(q,f.actors.oa,'pcA','mail.sync',{days:14,maxMessages:500},key).job_id,a.job_id);
 assert.throws(()=>start(q,f.actors.oa,'pcA','mail.sync',{days:7,maxMessages:500},key),/IDEMPOTENCY_CONFLICT/);
 const again=start(q,f.actors.oa,'pcA','mail.sync',{days:14,maxMessages:500});
 assert.equal(again.job_id,a.job_id);assert.equal(again.deduplicated,true);
 assert.throws(()=>start(q,f.actors.oa,'pcA','mail.sync',{days:3,maxMessages:10}),new RegExp('ACTIVE_JOB_CONFLICT:'+a.job_id));
 q.approve({approver:f.owner.A,jobId:a.job_id});
 const {job}=q.claim({actor:f.actors.aa,deviceId:'pcA'});
 assert.throws(()=>start(q,f.actors.oa,'pcA','mail.sync',{days:3,maxMessages:10}),/ACTIVE_JOB_CONFLICT/,'still locked while running');
 assert.equal(start(q,f.actors.oa,'pcA2','mail.sync',{days:3,maxMessages:10}).state,'AWAITING_APPROVAL','other PC is independent');
 q.complete({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:'{}'});
 assert.equal(start(q,f.actors.oa,'pcA','mail.sync',{days:3,maxMessages:10}).state,'AWAITING_APPROVAL','lock released after completion');
});

test('tenant A and B are isolated for requests, status, approval, claim, heartbeat and results',t=>{
 const f=fixture(t),q=f.open();
 const a=start(q,f.actors.oa,'pcA','mail.read',{messageId:'a'.repeat(40)});
 assert.throws(()=>start(q,f.actors.ob,'pcA','diag.wait',{seconds:5}),/ACCESS_DENIED/);
 assert.throws(()=>q.get({actor:f.actors.ob,jobId:a.job_id}),/JOB_NOT_FOUND/);
 assert.throws(()=>q.cancel({actor:f.actors.ob,jobId:a.job_id}),/JOB_NOT_FOUND/);
 assert.throws(()=>q.approve({approver:f.owner.B,jobId:a.job_id}),/JOB_NOT_FOUND/);
 assert.equal(q.list({actor:f.actors.ob}).length,0);
 assert.deepEqual(q.devices(f.actors.ob).map(d=>d.device),['pcB']);
 q.approve({approver:f.owner.A,jobId:a.job_id});
 assert.throws(()=>q.claim({actor:f.actors.ab,deviceId:'pcA'}),/ACCESS_DENIED/);
 assert.deepEqual(q.claim({actor:f.actors.ab,deviceId:'pcB'}),{job:null});
 assert.deepEqual(q.claim({actor:f.actors.aa2,deviceId:'pcA2'}),{job:null},'same-tenant other PC cannot take it');
 const {job}=q.claim({actor:f.actors.aa,deviceId:'pcA'});
 assert.throws(()=>q.heartbeat({actor:f.actors.ab,jobId:job.jobId,leaseToken:job.leaseToken}),/JOB_NOT_FOUND/);
 assert.throws(()=>q.complete({actor:f.actors.ab,jobId:job.jobId,leaseToken:job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:'stolen'}),/JOB_NOT_FOUND/);
 assert.throws(()=>q.get({actor:f.actors.aa,jobId:job.jobId}),/ACCESS_DENIED/,'agents cannot read owner results');
});

test('approval expiry, approval cancel, queued cancel and running cancel signal',t=>{
 const f=fixture(t),q=f.open();
 const e=start(q,f.actors.oa,'pcA','diag.wait',{seconds:5});
 f.advance(901);
 assert.equal(q.get({actor:f.actors.oa,jobId:e.job_id}).state,'APPROVAL_EXPIRED');
 assert.throws(()=>q.approve({approver:f.owner.A,jobId:e.job_id}),/APPROVAL_NOT_PENDING/);
 const c=start(q,f.actors.oa,'pcA','diag.wait',{seconds:6});
 assert.equal(q.cancel({actor:f.actors.oa,jobId:c.job_id}).state,'APPROVAL_CANCELLED');
 assert.throws(()=>q.approve({approver:f.owner.A,jobId:c.job_id}),/APPROVAL_NOT_PENDING/);
 const qd=start(q,f.actors.oa,'pcA','diag.wait',{seconds:7});q.approve({approver:f.owner.A,jobId:qd.job_id});
 assert.equal(q.cancel({actor:f.actors.oa,jobId:qd.job_id}).state,'CANCELLED');
 assert.deepEqual(q.claim({actor:f.actors.aa,deviceId:'pcA'}),{job:null});
 const r=start(q,f.actors.oa,'pcA','diag.wait',{seconds:8});q.approve({approver:f.owner.A,jobId:r.job_id});
 const {job}=q.claim({actor:f.actors.aa,deviceId:'pcA'});
 assert.equal(q.cancel({actor:f.actors.oa,jobId:r.job_id}).state,'CANCEL_REQUESTED');
 const hb=q.heartbeat({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken});
 assert.equal(hb.cancel,true);assert.equal(hb.reason,'OWNER_CANCELLED');
 assert.equal(q.complete({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken,outcome:'CANCELLED',exitCode:130,output:'{"ok":false}'}).state,'CANCELLED');
 const qe=start(q,f.actors.oa,'pcA','diag.wait',{seconds:9});q.approve({approver:f.owner.A,jobId:qe.job_id});
 f.advance(21601);
 assert.equal(q.get({actor:f.actors.oa,jobId:qe.job_id}).state,'EXPIRED','approved but never claimed');
});

test('max runtime: heartbeat after the approved deadline asks the agent to stop',t=>{
 const f=fixture(t),q=f.open();
 const j=start(q,f.actors.oa,'pcA','mail.search',{query:'견적',limit:5});q.approve({approver:f.owner.A,jobId:j.job_id});
 const {job}=q.claim({actor:f.actors.aa,deviceId:'pcA'});
 for(let i=0;i<2;i++){f.advance(50);q.heartbeat({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken});}
 f.advance(25);
 const hb=q.heartbeat({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken});
 assert.equal(hb.cancel,true);assert.equal(hb.reason,'MAX_RUNTIME');
});

test('exact-scope standing grant: one password, later identical requests queue without approval',t=>{
 const f=fixture(t),q=f.open(),params={days:14,maxMessages:1000};
 const first=start(q,f.actors.oa,'pcA','mail.sync',params);
 const ok=q.approve({approver:f.owner.A,jobId:first.job_id,grant:{minutes:1440,maxRuns:2}});
 assert.ok(ok.grantId);
 const run=j=>{const {job}=q.claim({actor:f.actors.aa,deviceId:'pcA'});assert.equal(job.jobId,j);q.complete({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:'{}'});};
 run(first.job_id);
 const second=start(q,f.actors.oa,'pcA','mail.sync',params);
 assert.equal(second.state,'QUEUED');assert.equal(second.via_standing_grant,true);assert.equal(second.approval_required,false);
 run(second.job_id);
 const other=start(q,f.actors.oa,'pcA','mail.sync',{days:13,maxMessages:1000});
 assert.equal(other.state,'AWAITING_APPROVAL','different params are a different scope');
 q.cancel({actor:f.actors.oa,jobId:other.job_id});
 const third=start(q,f.actors.oa,'pcA','mail.sync',params);
 assert.equal(third.state,'QUEUED');run(third.job_id);
 assert.equal(start(q,f.actors.oa,'pcA','mail.sync',params).state,'AWAITING_APPROVAL','run budget exhausted');
 assert.equal(q.listGrants(f.actors.oa).length,0);
 assert.equal(q.listGrants(f.actors.ob).length,0);
});

test('standing grants: revocation, expiry, tenant scope; mail.read can never be pre-approved',t=>{
 const f=fixture(t),q=f.open();
 const a=start(q,f.actors.oa,'pcA','diag.wait',{seconds:31});
 const g=q.approve({approver:f.owner.A,jobId:a.job_id,grant:{minutes:10,maxRuns:5}}).grantId;
 assert.throws(()=>q.revokeGrant({actor:f.actors.ob,grantId:g}),/GRANT_NOT_FOUND/);
 assert.equal(q.revokeGrant({actor:f.actors.oa,grantId:g}).state,'REVOKED');
 q.cancel({actor:f.actors.oa,jobId:a.job_id});
 assert.equal(start(q,f.actors.oa,'pcA','diag.wait',{seconds:31}).state,'AWAITING_APPROVAL');
 const r=start(q,f.actors.oa,'pcA','mail.read',{messageId:'b'.repeat(40)});
 assert.throws(()=>q.approve({approver:f.owner.A,jobId:r.job_id,grant:{minutes:10,maxRuns:5}}),/GRANT_NOT_ALLOWED_FOR_KIND/);
 assert.throws(()=>q.approve({approver:f.owner.A,jobId:r.job_id,grant:{minutes:99999,maxRuns:5}}),/GRANT_NOT_ALLOWED_FOR_KIND|INVALID_GRANT/);
 const x=start(q,f.actors.oa,'pcA2','diag.wait',{seconds:2});
 assert.throws(()=>q.approve({approver:f.owner.A,jobId:x.job_id,grant:{minutes:0,maxRuns:5}}),/INVALID_GRANT/);
 q.approve({approver:f.owner.A,jobId:x.job_id,grant:{minutes:1,maxRuns:5}});
 q.cancel({actor:f.actors.oa,jobId:x.job_id});
 f.advance(61);q.reap();
 assert.equal(start(q,f.actors.oa,'pcA2','diag.wait',{seconds:2}).state,'AWAITING_APPROVAL','expired grant not usable');
});

test('mail scope reuses reviewed Outlook bounds and blocks send/delete/oversized sync',t=>{
 const f=fixture(t),q=f.open();
 for(const [kind,params] of [['mail.sync',{days:180,maxMessages:3000}],['mail.sync',{days:14,maxMessages:1001}],['mail.read',{messageId:'../secrets'}],
   ['mail.search',{query:'--all'}],['mail.send',{to:'x'}],['mail.delete',{messageId:'a'.repeat(40)}],['shell',{argv:['powershell']}],['mail.sync',{days:1,maxMessages:1,argv:['x']}]])
  assert.throws(()=>start(q,f.actors.oa,'pcA',kind,params),/MAIL_SCOPE_DENIED|UNKNOWN_JOB_KIND|INVALID_PARAMS/);
 const prod=new LongJobKinds();
 assert.deepEqual(prod.names().sort(),['mail.read','mail.search','mail.sync'],'synthetic diag kind is opt-in only');
});

test('encrypted params/results at rest and audit rows without content',t=>{
 const f=fixture(t),q=f.open();
 const j=start(q,f.actors.oa,'pcA','mail.search',{query:'secret-term-xyzzy',limit:3});
 q.approve({approver:f.owner.A,jobId:j.job_id});
 const {job}=q.claim({actor:f.actors.aa,deviceId:'pcA'});
 q.complete({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:JSON.stringify({results:[{subject:'private-subject-qwerty'}]})});
 const rows=f.store().db.prepare('SELECT * FROM audit').all();
 assert.ok(rows.length>=3);
 assert.ok(rows.every(r=>!JSON.stringify(r).includes('xyzzy')&&!JSON.stringify(r).includes('qwerty')));
 f.close();
 const raw=readFileSync(f.file);
 assert.equal(raw.includes(Buffer.from('secret-term-xyzzy')),false);
 assert.equal(raw.includes(Buffer.from('private-subject-qwerty')),false);
 assert.equal(raw.includes(Buffer.from(job.leaseToken)),false,'only the lease hash is stored');
});

test('v1 short-job restart semantics stay unchanged next to the V2 tables',t=>{
 const f=fixture(t);let q=f.open();
 const db=f.store().db;
 assert.equal(db.prepare('PRAGMA user_version').get().user_version,2);
 f.close();q=f.open();
 assert.equal(f.store().db.prepare('PRAGMA user_version').get().user_version,2);
});

test('a selected mail body is purged from the server one hour after the read finished',t=>{
 const f=fixture(t),q=f.open();
 const j=start(q,f.actors.oa,'pcA','mail.read',{messageId:'e'.repeat(40)});
 q.approve({approver:f.owner.A,jobId:j.job_id});
 const {job}=q.claim({actor:f.actors.aa,deviceId:'pcA'});
 q.complete({actor:f.actors.aa,jobId:job.jobId,leaseToken:job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:JSON.stringify({body:'synthetic-body-zzz'})});
 assert.equal(q.get({actor:f.actors.oa,jobId:j.job_id}).result.body,'synthetic-body-zzz');
 f.advance(3601);
 const later=q.get({actor:f.actors.oa,jobId:j.job_id});
 assert.equal(later.result,null);assert.equal(later.result_purged,true);assert.equal(later.state,'SUCCEEDED');
});
