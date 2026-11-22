import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {DatabaseSync} from 'node:sqlite';
import {TenantDirectory} from './tenant-artifact-core.mjs';
import {StagingSqlite} from './staging-sqlite.mjs';
import {LongJobQueue} from './durable-long-jobs.mjs';
import {LongJobKinds,FLEET_KIND_NAMES} from './long-job-kinds.mjs';
import {FleetPolicy,recommend} from './fleet-policy.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const KINDS=['fleet.inventory','fleet.cpu_bench','fleet.blob_verify'];
const POLICY={version:1,denylist:{hostnames:['DENIED-PC']},devices:[
 {id:'fast',hostname:'FAST',status:'ACTIVE',maxConcurrent:4,gpuSlots:0,allowedKinds:KINDS,dataClasses:['public','synthetic']},
 {id:'slow',hostname:'SLOW',status:'ACTIVE',maxConcurrent:4,gpuSlots:0,allowedKinds:KINDS,dataClasses:['public','synthetic']},
 {id:'new',hostname:'NEW',status:'ACTIVE',maxConcurrent:2,gpuSlots:0,allowedKinds:KINDS,dataClasses:['public','synthetic']}]};
const policy=()=>new FleetPolicy(structuredClone(POLICY),{knownKinds:new Set(FLEET_KIND_NAMES)});
const inv=(cores)=>({captured:990,snapshot:{cpu:{logical:cores,load_pct:5},ram:{available_mib:16000},gpus:[]}});
const busy=(device,n,units=40,state='RUNNING')=>Array.from({length:n},()=>({device,state,cpu:1,ramMiB:0,workUnits:units}));

test('throughput placement: a 3x faster PC takes queued work before a slow PC takes it idle',()=>{
 const p=policy(),inventories=new Map([['fast',inv(10)],['slow',inv(16)]]);
 const tp=new Map([['fast',{unitSeconds:0.13,samples:8}],['slow',{unitSeconds:0.42,samples:8}]]);
 const job={kind:'fleet.cpu_bench',workUnits:40};
 // fast is full (4 running) but finishes its backlog + this job sooner: (160/4+40)*0.13=10.4 s vs slow idle 40*0.42=16.8 s
 const r=recommend(p,job,inventories,busy('fast',4),1000,{throughput:tp});
 assert.equal(r.placement,'throughput');
 assert.deepEqual(r.candidates.map(c=>c.device),['fast','slow']);
 assert.equal(r.candidates[0].finish_estimate_s,10.4);
 // once fast has 8 open (2 x 4, capped at 5 open per PC) it is full and slow is used
 const r2=recommend(p,job,inventories,busy('fast',5),1000,{throughput:tp});
 assert.equal(r2.candidates[0].device,'slow');
 assert.equal(r2.excluded.find(e=>e.device==='fast').reason,'CONCURRENCY_FULL');
 // the first version (cores) would have sent it to the idle PC with more cores
 assert.equal(recommend(p,job,inventories,busy('fast',3),1000,{placement:'cores'}).candidates[0].device,'slow');
});

test('an unmeasured PC is explored with exactly one job, then judged by its measurement',()=>{
 const p=policy(),inventories=new Map([['fast',inv(10)],['new',inv(8)]]);
 const tp=new Map([['fast',{unitSeconds:0.13,samples:8}]]);
 const job={kind:'fleet.cpu_bench',workUnits:40};
 assert.equal(recommend(p,job,inventories,[],1000,{throughput:tp}).candidates[0].device,'new');
 const r=recommend(p,job,inventories,busy('new',1),1000,{throughput:tp});
 assert.equal(r.excluded.find(e=>e.device==='new').reason,'MEASURING_THROUGHPUT');
 assert.deepEqual(r.candidates.map(c=>c.device),['fast']);
 assert.throws(()=>recommend(p,job,inventories,[],1000,{placement:'magic'}),/INVALID_PLACEMENT/);
});

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'rian-fleet-tp-')),file=join(dir,'state.db'),key=randomBytes(32).toString('hex');
 const ids=['owner','a-fast','a-slow'],tkn=Object.fromEntries(ids.map(x=>[x,randomBytes(40).toString('base64url')]));
 const dev={'a-fast':'fast','a-slow':'slow'};
 const directory=new TenantDirectory({devices:['fast','slow','new'].map(id=>({id,tenantId:'R'})),
  principals:ids.map(id=>({id,tenantId:'R',kind:id==='owner'?'owner':'agent',...(dev[id]?{deviceId:dev[id]}:{}),tokenSha256:sha(tkn[id])}))});
 const a=Object.fromEntries(ids.map(x=>[x,directory.authenticate('Bearer '+tkn[x])]));
 let ms=1763900000000,store=null;
 const open=()=>{store=new StagingSqlite({filename:file,encryptionKeyHex:key});
  return new LongJobQueue({directory,store,kinds:new LongJobKinds({allowFleet:true}),clock:()=>ms,fleet:policy()});};
 t.after(()=>{if(store)store.close();rmSync(dir,{recursive:true,force:true});});
 return {open,a,file,key,advance:s=>{ms+=s*1000;},close:()=>{store.close();store=null;}};
}

test('the queue measures seconds per work unit from real runs, and work units come from the kind',t=>{
 const f=fixture(t),q=f.open(),appr={tenantId:'R',ownerId:'owner'};
 const run=(dev,chunk,units,secs)=>{
  const j=q.request({actor:f.a.owner,deviceId:dev,kind:'fleet.cpu_bench',params:{chunk,units},fleet:{workUnits:999999}});
  q.approve({approver:appr,jobId:j.job_id});
  const c=q.claim({actor:f.a['a-'+dev],deviceId:dev});
  f.advance(secs);
  q.complete({actor:f.a['a-'+dev],jobId:c.job.jobId,leaseToken:c.job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:'{"ok":true}'});
  return j;
 };
 const j=run('fast',1,40,5);run('fast',2,40,6);run('fast',3,40,5);run('slow',4,40,17);
 assert.equal(q.fleetActive(f.a.owner).length,0);
 assert.equal(q.get({actor:f.a.owner,jobId:j.job_id}).fleet.reserved.cpu,1);
 const tp=q.fleetThroughput({actor:f.a.owner,kind:'fleet.cpu_bench'});
 assert.deepEqual(tp.get('fast'),{unitSeconds:0.125,samples:3});         // median of 5/40, 6/40, 5/40
 assert.deepEqual(tp.get('slow'),{unitSeconds:0.425,samples:1});
 // the caller's workUnits (999999) was ignored: cpu_bench sizes itself by `units`
 const open=q.request({actor:f.a.owner,deviceId:'slow',kind:'fleet.cpu_bench',params:{chunk:9,units:7}});
 assert.equal(q.fleetActive(f.a.owner).find(x=>x.job_id===open.job_id).workUnits,7);
});

test('an older fleet_jobs table gains work_units in place',t=>{
 const dir=mkdtempSync(join(tmpdir(),'rian-fleet-mig-')),file=join(dir,'old.db');
 t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const db=new DatabaseSync(file);
 db.exec('CREATE TABLE fleet_jobs (job_id TEXT PRIMARY KEY, priority INTEGER NOT NULL DEFAULT 0, needs_gpu INTEGER NOT NULL DEFAULT 0, cpu INTEGER NOT NULL DEFAULT 1, ram_mib INTEGER NOT NULL DEFAULT 0, vram_mib INTEGER NOT NULL DEFAULT 0, data_class TEXT NOT NULL, gpu_release TEXT)');
 db.close();
 const store=new StagingSqlite({filename:file,encryptionKeyHex:randomBytes(32).toString('hex')});
 assert.ok(store.db.prepare("SELECT 1 FROM pragma_table_info('fleet_jobs') WHERE name='work_units'").get());
 store.close();
});

test('integrity kind: store is a name only, the shard must exist',()=>{
 const k=new LongJobKinds({allowFleet:true});
 assert.deepEqual(k.canonical('fast','fleet.blob_verify',{store:'ollama-c',shard:1,shards:4}).params,{shard:1,shards:4,store:'ollama-c'});
 for(const bad of [{store:'C:\\RIAN',shard:0,shards:1},{store:'../x',shard:0,shards:1},{store:'ok',shard:4,shards:4},{store:'ok',shard:0}])
  assert.throws(()=>k.canonical('fast','fleet.blob_verify',bad),/INVALID_PARAMS/);
});
