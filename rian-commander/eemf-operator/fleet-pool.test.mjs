import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {TenantDirectory} from './tenant-artifact-core.mjs';
import {StagingSqlite} from './staging-sqlite.mjs';
import {LongJobQueue} from './durable-long-jobs.mjs';
import {LongJobKinds,FLEET_KIND_NAMES} from './long-job-kinds.mjs';
import {FleetPolicy,recommend,verifyGpuRelease} from './fleet-policy.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const ALL=['fleet.inventory','fleet.cpu_bench','fleet.gpu_probe','youngmin.qlora_probe'];
// Synthetic names only: the real roster lives in the central node's configuration, not in Git.
const POLICY={version:1,denylist:{hostnames:['DENIED-PC']},quarantineKinds:['fleet.inventory'],devices:[
 {id:'hub',hostname:'hub-host.local',role:'central',status:'ACTIVE',maxConcurrent:2,gpuSlots:0,allowedKinds:['fleet.inventory','fleet.cpu_bench'],dataClasses:['public','synthetic','private'],privateDataApproved:true},
 {id:'gpu1',hostname:'GPU-HOST-1',role:'gpu',status:'ACTIVE',maxConcurrent:2,gpuSlots:1,allowedKinds:ALL,dataClasses:['public','synthetic'],protectedGpuProcesses:['llama-server']},
 {id:'gpu2',hostname:'GPU-HOST-2',role:'gpu',status:'ACTIVE',maxConcurrent:1,gpuSlots:1,allowedKinds:ALL,dataClasses:['public','synthetic']},
 {id:'quar',hostname:'QUAR-HOST',role:'cpu',status:'QUARANTINED',quarantineReason:'security alert not cleared',maxConcurrent:1,allowedKinds:['fleet.inventory','fleet.cpu_bench'],dataClasses:['synthetic']}]};
const policy=()=>new FleetPolicy(structuredClone(POLICY),{knownKinds:new Set(FLEET_KIND_NAMES)});

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'rian-fleet-')),file=join(dir,'state.db'),key=randomBytes(32).toString('hex');
 const ids=['owner','a-hub','a-gpu1','a-gpu2','a-quar','a-denied'];
 const tkn=Object.fromEntries(ids.map(x=>[x,randomBytes(40).toString('base64url')]));
 const dev={'a-hub':'hub','a-gpu1':'gpu1','a-gpu2':'gpu2','a-quar':'quar','a-denied':'DENIED-PC'};
 const directory=new TenantDirectory({devices:['hub','gpu1','gpu2','quar','DENIED-PC'].map(id=>({id,tenantId:'R'})),
  principals:ids.map(id=>({id,tenantId:'R',kind:id==='owner'?'owner':'agent',...(dev[id]?{deviceId:dev[id]}:{}),tokenSha256:sha(tkn[id])}))});
 const a=Object.fromEntries(ids.map(x=>[x,directory.authenticate('Bearer '+tkn[x])]));
 let ms=1763800000000,store=null;
 const open=()=>{store=new StagingSqlite({filename:file,encryptionKeyHex:key});
  return new LongJobQueue({directory,store,kinds:new LongJobKinds({allowFleet:true}),clock:()=>ms,fleet:policy()});};
 t.after(()=>{if(store)store.close();rmSync(dir,{recursive:true,force:true});});
 return {open,a,advance:s=>{ms+=s*1000;},approver:{tenantId:'R',ownerId:'owner'},close:()=>{store.close();store=null;}};
}
const req=(f,q,device,kind,params,fleet)=>q.request({actor:f.a.owner,deviceId:device,kind,params,fleet});
const approve=(f,q,j)=>q.approve({approver:f.approver,jobId:j.job_id});
const queued=(f,q,device,kind,params,fleet)=>{const j=req(f,q,device,kind,params,fleet);approve(f,q,j);return j;};

test('policy fails closed: a denylist is mandatory and a denied host can never be configured',()=>{
 assert.throws(()=>new FleetPolicy({...structuredClone(POLICY),denylist:undefined}),/DENYLIST_REQUIRED/);
 assert.throws(()=>new FleetPolicy({...structuredClone(POLICY),denylist:{hostnames:[],deviceIds:[]}}),/DENYLIST_REQUIRED/);
 const listed=structuredClone(POLICY);listed.devices[0].hostname='denied-pc.local';
 assert.throws(()=>new FleetPolicy(listed),/DENIED_DEVICE_LISTED/);
 const priv=structuredClone(POLICY);priv.devices[1].dataClasses.push('private');
 assert.throws(()=>new FleetPolicy(priv),/PRIVATE_NOT_APPROVED/,'private data needs an explicit approval flag');
 const p=policy();
 for(const n of ['DENIED-PC','denied-pc','Denied-PC.local','denied-pc.local.local','DENIED-PC.'])assert.equal(p.isDenied(n),true,n);
 assert.throws(()=>p.device('DENIED-PC'),/DEVICE_DENIED/);
 assert.deepEqual(p.deviceKinds().get('quar'),['fleet.inventory'],'a quarantined PC can only be inspected');
 assert.throws(()=>p.assertDispatchable('gpu1','fleet.cpu_bench',{dataClass:'private'}),/DATA_CLASS_NOT_ALLOWED/);
 assert.equal(p.assertDispatchable('hub','fleet.cpu_bench',{dataClass:'private'}).id,'hub');
});

test('denied and quarantined PCs get no work at request time and cannot claim',t=>{
 const f=fixture(t),q=f.open();
 assert.throws(()=>req(f,q,'DENIED-PC','fleet.inventory',{}),/DEVICE_DENIED/);
 assert.throws(()=>q.claim({actor:f.a['a-denied'],deviceId:'DENIED-PC'}),/DEVICE_DENIED/);
 assert.throws(()=>req(f,q,'quar','fleet.cpu_bench',{chunk:0,units:1}),/DEVICE_QUARANTINED/);
 assert.equal(req(f,q,'quar','fleet.inventory',{}).state,'AWAITING_APPROVAL','inventory is how quarantine gets reviewed');
 assert.throws(()=>req(f,q,'hub','fleet.gpu_probe',{mib:64}),/KIND_NOT_ALLOWED_FOR_DEVICE/);
 assert.throws(()=>req(f,q,'gpu1','fleet.cpu_bench',{chunk:0,units:1},{dataClass:'private'}),/DATA_CLASS_NOT_ALLOWED/);
 assert.throws(()=>req(f,q,'gpu1','fleet.cpu_bench',{chunk:0,units:1},{argv:['rm']}),/INVALID_FLEET_REQUEST/);
});

test('per-device concurrency limit holds extra jobs QUEUED and releases them as runs finish',t=>{
 const f=fixture(t),q=f.open();
 const jobs=[0,1,2].map(i=>queued(f,q,'hub','fleet.cpu_bench',{chunk:i,units:1}));
 const c1=q.claim({actor:f.a['a-hub'],deviceId:'hub'}),c2=q.claim({actor:f.a['a-hub'],deviceId:'hub'});
 assert.ok(c1.job&&c2.job);
 assert.deepEqual(q.claim({actor:f.a['a-hub'],deviceId:'hub'}),{job:null,held:'CONCURRENCY_LIMIT'});
 q.complete({actor:f.a['a-hub'],jobId:c1.job.jobId,leaseToken:c1.job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:'{"ok":true}'});
 const c3=q.claim({actor:f.a['a-hub'],deviceId:'hub'});
 assert.equal(c3.job.jobId,jobs[2].job_id);
 assert.equal(new Set([c1,c2,c3].map(c=>c.job.jobId)).size,3,'each job dispatched exactly once');
});

test('higher priority is claimed first; identical work units are deduplicated, distinct chunks are not',t=>{
 const f=fixture(t),q=f.open();
 const low=queued(f,q,'gpu2','fleet.cpu_bench',{chunk:1,units:1},{priority:-5});
 const high=queued(f,q,'gpu2','fleet.cpu_bench',{chunk:2,units:1},{priority:50});
 assert.equal(req(f,q,'gpu2','fleet.cpu_bench',{chunk:2,units:1},{priority:50}).deduplicated,true);
 assert.equal(q.claim({actor:f.a['a-gpu2'],deviceId:'gpu2'}).job.jobId,high.job_id);
 assert.equal(q.get({actor:f.a.owner,jobId:low.job_id}).fleet.priority,-5);
});

test('GPU work: one per PC, memory hand-back is verified, and an unverified GPU only accepts the probe',t=>{
 const f=fixture(t),q=f.open();
 const p1=queued(f,q,'gpu1','fleet.gpu_probe',{mib:64});
 assert.throws(()=>req(f,q,'gpu1','youngmin.qlora_probe',{seqLen:256,batch:1,steps:2,rank:16,gradCheckpointing:true}),/ACTIVE_JOB_CONFLICT/);
 const c=q.claim({actor:f.a['a-gpu1'],deviceId:'gpu1'});
 const bad=JSON.stringify({ok:true,gpu_release:{before_mib:600,after_mib:4800,leftover_pids:[4242]}});
 const done=q.complete({actor:f.a['a-gpu1'],jobId:c.job.jobId,leaseToken:c.job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:bad});
 assert.equal(done.gpu_release.state,'NOT_RETURNED');
 assert.equal(q.get({actor:f.a.owner,jobId:p1.job_id}).fleet.gpu_release.state,'NOT_RETURNED');
 const train=queued(f,q,'gpu1','youngmin.qlora_probe',{seqLen:256,batch:1,steps:2,rank:16,gradCheckpointing:true});
 assert.deepEqual(q.claim({actor:f.a['a-gpu1'],deviceId:'gpu1'}),{job:null,held:'GPU_RELEASE_UNVERIFIED'});
 q.cancel({actor:f.a.owner,jobId:train.job_id});
 queued(f,q,'gpu1','fleet.gpu_probe',{mib:32});
 const probe=q.claim({actor:f.a['a-gpu1'],deviceId:'gpu1'});
 assert.equal(probe.job.kind,'fleet.gpu_probe','the hand-back probe is still allowed');
 const ok=JSON.stringify({ok:true,gpu_release:{before_mib:600,after_mib:640,leftover_pids:[]}});
 assert.equal(q.complete({actor:f.a['a-gpu1'],jobId:probe.job.jobId,leaseToken:probe.job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:ok}).gpu_release.state,'VERIFIED');
 queued(f,q,'gpu1','youngmin.qlora_probe',{seqLen:256,batch:1,steps:2,rank:16,gradCheckpointing:true});
 assert.equal(q.claim({actor:f.a['a-gpu1'],deviceId:'gpu1'}).job.kind,'youngmin.qlora_probe');
});

test('the QLoRA probe always needs its own owner approval; a standing grant cannot pre-approve it',t=>{
 const f=fixture(t),q=f.open();
 const j=req(f,q,'gpu2','youngmin.qlora_probe',{seqLen:256,batch:1,steps:2,rank:16,gradCheckpointing:true});
 assert.equal(j.approval_required,true);
 assert.throws(()=>q.approve({approver:f.approver,jobId:j.job_id,grant:{minutes:60,maxRuns:5}}),/GRANT/);
});

test('a lost connection never re-runs a job; the late authentic result is still collected once',t=>{
 const f=fixture(t),q=f.open();
 const j=queued(f,q,'hub','fleet.cpu_bench',{chunk:7,units:3});
 const c=q.claim({actor:f.a['a-hub'],deviceId:'hub'});
 f.advance(120);                                           // agent unreachable past its lease
 assert.deepEqual(q.claim({actor:f.a['a-hub'],deviceId:'hub'}),{job:null});
 assert.equal(q.get({actor:f.a.owner,jobId:j.job_id}).state,'UNKNOWN_DO_NOT_RETRY');
 const out='{"ok":true,"digest":"ab"}';
 assert.equal(q.complete({actor:f.a['a-hub'],jobId:c.job.jobId,leaseToken:c.job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:out}).late,true);
 assert.equal(q.complete({actor:f.a['a-hub'],jobId:c.job.jobId,leaseToken:c.job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:out}).duplicate,true);
 f.close();const q2=f.open();                              // and across a server restart
 assert.deepEqual(q2.claim({actor:f.a['a-hub'],deviceId:'hub'}),{job:null});
});

test('recommendation places work by live headroom and says why every other PC was skipped',()=>{
 const p=policy(),now=2000;
 const inv=(cores,load,availMiB,gpus)=>({captured:now-30,snapshot:{cpu:{logical:cores,load_pct:load},ram:{available_mib:availMiB},gpus}});
 const inventories=new Map([['hub',inv(10,20,20000,[])],
  ['gpu1',inv(20,10,30000,[{vram_total_mib:12288,vram_used_mib:9000,compute_processes:['llama-server.exe']}])],
  ['gpu2',inv(8,50,6000,[{vram_total_mib:8192,vram_used_mib:600,compute_processes:[]}])]]);
 const gpu=recommend(p,{kind:'fleet.gpu_probe',needsGpu:true,vramMiB:1024},inventories,[],now);
 assert.deepEqual(gpu.candidates.map(c=>c.device),['gpu2']);
 const why=Object.fromEntries(gpu.excluded.map(e=>[e.device,e.reason]));
 assert.equal(why.gpu1,'GPU_PROTECTED_PROCESS','a production llama-server keeps its GPU');
 assert.equal(why.hub,'KIND_NOT_ALLOWED_FOR_DEVICE');assert.equal(why.quar,'DEVICE_QUARANTINED');
 const cpu=recommend(p,{kind:'fleet.cpu_bench',cpu:2,ramMiB:512},inventories,[{device:'hub',cpu:1,ramMiB:0},{device:'hub',cpu:1,ramMiB:0}],now);
 assert.equal(Object.fromEntries(cpu.excluded.map(e=>[e.device,e.reason])).hub,'CONCURRENCY_FULL');
 assert.equal(cpu.candidates[0].device,'gpu1','most free cores wins');
 const stale=recommend(p,{kind:'fleet.cpu_bench'},new Map([['hub',{captured:now-5000,snapshot:{}}]]),[],now);
 assert.equal(stale.excluded.find(e=>e.device==='hub').reason,'INVENTORY_STALE');
 assert.equal(stale.excluded.find(e=>e.device==='gpu2').reason,'NO_INVENTORY');
});

test('GPU hand-back verdicts',()=>{
 assert.equal(verifyGpuRelease({gpu_release:{before_mib:500,after_mib:600,leftover_pids:[]}}).state,'VERIFIED');
 assert.equal(verifyGpuRelease({gpu_release:{before_mib:500,after_mib:900,leftover_pids:[]}}).state,'NOT_RETURNED');
 assert.equal(verifyGpuRelease({gpu_release:{before_mib:500,after_mib:500,leftover_pids:[1]}}).state,'NOT_RETURNED');
 assert.equal(verifyGpuRelease({ok:false}).state,'NOT_REPORTED');
});
