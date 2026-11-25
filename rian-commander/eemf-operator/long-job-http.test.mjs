import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {TenantDirectory} from './tenant-artifact-core.mjs';
import {StagingSqlite} from './staging-sqlite.mjs';
import {LongJobQueue} from './durable-long-jobs.mjs';
import {LongJobKinds} from './long-job-kinds.mjs';
import {FleetPolicy} from './fleet-policy.mjs';
import {createLongJobHandler,hashApprovalPassword,clientRefFor} from './long-job-http.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const ORIGIN='https://rian-commander-tenant-staging.example.test';
function fixture(t, withFleet=false){
 const dir=mkdtempSync(join(tmpdir(),'rian-ljhttp-'));
 const tkn=Object.fromEntries(['oa','ob','aa','ab'].map(x=>[x,randomBytes(40).toString('base64url')]));
 const directory=new TenantDirectory({devices:[{id:'pcA',tenantId:'A'},{id:'pcB',tenantId:'B'}],
  principals:[['oa','A','owner'],['ob','B','owner'],['aa','A','agent','pcA'],['ab','B','agent','pcB']]
   .map(([id,tenantId,kind,deviceId])=>({id,tenantId,kind,...(deviceId?{deviceId}:{}),tokenSha256:sha(tkn[id])}))});
 const store=new StagingSqlite({filename:join(dir,'s.db'),encryptionKeyHex:randomBytes(32).toString('hex')});
 const kinds=new LongJobKinds({allowDiagnostics:true,allowFleet:withFleet});
 const fleet=withFleet?new FleetPolicy({version:1,denylist:{hostnames:['DENIED-PC']},devices:[
  {id:'pcA',hostname:'pcA',status:'QUARANTINED',allowedKinds:['fleet.inventory'],maxConcurrent:1,gpuSlots:0,dataClasses:['synthetic']},
  {id:'pcB',hostname:'pcB',status:'QUARANTINED',allowedKinds:['fleet.inventory'],maxConcurrent:1,gpuSlots:0,dataClasses:['synthetic']}
 ]},{knownKinds:new Set(kinds.names())}):null;
 const queue=new LongJobQueue({directory,store,kinds,fleet});
 const pwA='synthetic-owner-A-password-'+randomBytes(4).toString('hex'),pwB='synthetic-owner-B-password-'+randomBytes(4).toString('hex');
 const approvers=[{tenantId:'A',ownerId:'oa',...hashApprovalPassword(pwA)},{tenantId:'B',ownerId:'ob',...hashApprovalPassword(pwB)}];
 const handler=createLongJobHandler({directory,queue,approvers,publicOrigin:ORIGIN,formSecret:randomBytes(48).toString('hex')});
 t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
 const rpc=async(who,method,params={},extra={})=>{
  const r=await handler(new Request(ORIGIN+'/v2/mcp',{method:'POST',headers:{authorization:'Bearer '+tkn[who],'content-type':'application/json',...extra},body:JSON.stringify({jsonrpc:'2.0',id:7,method,params})}));
  return {status:r.status,body:r.status===202?null:await r.json()};
 };
 const tool=async(who,name,args)=>{
  const {body}=await rpc(who,'tools/call',{name,arguments:args});
  const textOut=body.result.content[0].text;
  return body.result.isError?{error:textOut}:JSON.parse(textOut);
 };
 const agentCall=async(who,path,payload)=>{
  const r=await handler(new Request(ORIGIN+path,{method:'POST',headers:{authorization:'Bearer '+tkn[who],'content-type':'application/json'},body:JSON.stringify(payload)}));
  return {status:r.status,body:await r.json()};
 };
 const approvePage=async(jobId)=>{
  const r=await handler(new Request(ORIGIN+'/v2/approve/'+jobId));
  const html=await r.text();
  return {status:r.status,html,ticket:/name="ticket" value="([^"]+)"/.exec(html)?.[1]};
 };
 const submit=async(jobId,fields,origin=ORIGIN)=>{
  const r=await handler(new Request(ORIGIN+'/v2/approve/'+jobId,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',...(origin?{origin}:{})},body:new URLSearchParams(fields).toString()}));
  return {status:r.status,html:await r.text()};
 };
 return {tkn,rpc,tool,agentCall,approvePage,submit,pwA,pwB,queue,directory,handler};
}

test('MCP: tools list has no approve tool; start returns job_id + approval_url immediately',async t=>{
 const f=fixture(t);
 const list=await f.rpc('oa','tools/list');
 const names=list.body.result.tools.map(x=>x.name);
 assert.deepEqual(names,['rian_v2_devices','rian_v2_start_job','rian_v2_job_status','rian_v2_list_jobs','rian_v2_cancel_job','rian_v2_list_grants','rian_v2_revoke_grant']);
 assert.ok(!names.some(n=>/approve/.test(n)));
 const t0=Date.now();
 const s=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'diag.wait',params:{seconds:60}});
 assert.ok(Date.now()-t0<2000,'no synchronous execution wait');
 assert.equal(s.state,'AWAITING_APPROVAL');
 assert.equal(s.approval_url,ORIGIN+'/v2/approve/'+s.job_id);
 assert.match(s.guidance,/승인/);
 assert.equal((await f.rpc('oa','notifications/initialized')).status,202);
 assert.equal((await f.rpc('aa','tools/list')).status,401,'agent token is not an owner');
 const anon=await f.handler(new Request(ORIGIN+'/v2/mcp',{method:'POST',headers:{'content-type':'application/json'},body:'{}'}));
 assert.equal(anon.status,401,'anonymous MCP call rejected');
});

test('scoped inventory MCP uses existing approval and rejects other arguments or tenant',async t=>{
 const f=fixture(t,true);
 const list=await f.rpc('oa','tools/list');
 assert.ok(list.body.result.tools.some(x=>x.name==='rian_v2_request_inventory'));
 const result=await f.tool('oa','rian_v2_request_inventory',{device:'pcA'});
 assert.equal(result.state,'AWAITING_APPROVAL');
 assert.equal(result.approval_url,ORIGIN+'/v2/approve/'+result.job_id);
 assert.equal((await f.tool('oa','rian_v2_request_inventory',{device:'pcA',argv:['cmd']})).error,'INVALID_ARGUMENTS');
 assert.equal((await f.tool('oa','rian_v2_request_inventory',{device:'auto'})).error,'INVALID_ARGUMENTS');
 assert.equal((await f.tool('oa','rian_v2_request_inventory',{device:'pcB'})).error,'NOT_FOUND');
 assert.equal((await f.agentCall('aa','/v2/agent/claim',{deviceId:'pcA'})).body.job,null);
 const page=await f.approvePage(result.job_id);
 assert.equal((await f.submit(result.job_id,{ticket:page.ticket,password:f.pwA})).status,200);
 const claim=await f.agentCall('aa','/v2/agent/claim',{deviceId:'pcA'});
 assert.equal(claim.body.job.kind,'fleet.inventory');
 assert.deepEqual(claim.body.job.params,{});
});

test('real browsers can submit the approval form (Origin is not nulled by the referrer policy)',async t=>{
 const f=fixture(t);
 const s=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.sync',params:{days:1,maxMessages:1}});
 const get=await f.handler(new Request(ORIGIN+'/v2/approve/'+s.job_id));
 // Fetch spec: a POST under referrer policy "no-referrer" carries "Origin: null".
 assert.equal(get.headers.get('referrer-policy'),'same-origin');
 const ticket=/name="ticket" value="([^"]+)"/.exec(await get.text())[1];
 const post=(headers,password=f.pwA)=>f.handler(new Request(ORIGIN+'/v2/approve/'+s.job_id,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',...headers},body:new URLSearchParams({ticket,password})}));
 assert.equal((await post({origin:'null','sec-fetch-site':'cross-site'})).status,403);
 assert.equal((await post({origin:'null'})).status,403,'null origin without browser fetch metadata stays blocked');
 assert.equal((await post({origin:'https://evil.example','sec-fetch-site':'same-origin'})).status,403);
 const ok=await post({origin:'null','sec-fetch-site':'same-origin'});
 assert.equal(ok.status,200);assert.match(await ok.text(),/승인 완료/);
});

test('approval page: exact scope, origin check, CSRF ticket, wrong password, then queued',async t=>{
 const f=fixture(t);
 const s=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.sync',params:{days:14,maxMessages:1000}});
 const p=await f.approvePage(s.job_id);
 assert.equal(p.status,200);
 assert.match(p.html,/pcA/);assert.match(p.html,/최근 14일, 최대 1000건/);assert.match(p.html,/메일 발송·삭제/);
 assert.equal((await f.submit(s.job_id,{ticket:p.ticket,password:f.pwA},'https://evil.example')).status,403);
 assert.equal((await f.submit(s.job_id,{ticket:p.ticket,password:f.pwA},null)).status,403);
 assert.match((await f.submit(s.job_id,{ticket:'forged.1.2.3',password:f.pwA})).html,/만료/);
 assert.match((await f.submit(s.job_id,{ticket:p.ticket,password:f.pwB})).html,/일치하지 않습니다/,'tenant B password cannot approve tenant A');
 assert.equal((await f.tool('oa','rian_v2_job_status',{job_id:s.job_id})).state,'AWAITING_APPROVAL');
 const ok=await f.submit(s.job_id,{ticket:p.ticket,password:f.pwA,standing:'1',minutes:'1440',runs:'3'});
 assert.equal(ok.status,200);assert.match(ok.html,/승인 완료/);assert.match(ok.html,/반복 승인 3회/);
 assert.equal((await f.tool('oa','rian_v2_job_status',{job_id:s.job_id})).state,'QUEUED');
 assert.equal((await f.approvePage(s.job_id)).status,409,'approval cannot be replayed');
 const grants=await f.tool('oa','rian_v2_list_grants',{});
 assert.equal(grants.grants.length,1);assert.equal(grants.grants[0].runs_left,3);
});

test('password attempts are rate limited per tenant and client',async t=>{
 const f=fixture(t);
 const s=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'diag.wait',params:{seconds:3}});
 const {ticket}=await f.approvePage(s.job_id);
 for(let i=0;i<5;i++)await f.submit(s.job_id,{ticket,password:'wrong-password-but-long-enough'});
 assert.equal((await f.submit(s.job_id,{ticket,password:f.pwA})).status,429);
});

test('agent API: claim, heartbeat with progress, complete; owner sees result via MCP',async t=>{
 const f=fixture(t);
 const s=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'diag.wait',params:{seconds:30},request_key:'req-'+randomBytes(8).toString('hex')});
 const {ticket}=await f.approvePage(s.job_id);
 await f.submit(s.job_id,{ticket,password:f.pwA});
 assert.equal((await f.agentCall('ab','/v2/agent/claim',{deviceId:'pcB'})).body.job,null);
 assert.equal((await f.agentCall('ab','/v2/agent/claim',{deviceId:'pcA'})).status,404,'other tenant agent denied');
 assert.equal((await f.agentCall('oa','/v2/agent/claim',{deviceId:'pcA'})).status,401,'owner token is not an agent');
 const c=await f.agentCall('aa','/v2/agent/claim',{deviceId:'pcA'});
 const job=c.body.job;assert.equal(job.jobId,s.job_id);
 const hb=await f.agentCall('aa','/v2/agent/jobs/'+job.jobId+'/heartbeat',{leaseToken:job.leaseToken,progress:{percent:40,stage:'waiting',done:12,total:30}});
 assert.equal(hb.status,200);assert.equal(hb.body.cancel,false);
 assert.equal((await f.agentCall('aa','/v2/agent/jobs/'+job.jobId+'/heartbeat',{leaseToken:randomBytes(32).toString('base64url')})).status,409);
 assert.equal((await f.agentCall('aa','/v2/agent/jobs/'+job.jobId+'/heartbeat',{leaseToken:job.leaseToken,progress:{stage:'<script>'}})).status,400);
 const mid=await f.tool('oa','rian_v2_job_status',{job_id:s.job_id});
 assert.deepEqual(mid.progress,{percent:40,stage:'waiting',done:12,total:30});
 assert.equal((await f.tool('ob','rian_v2_job_status',{job_id:s.job_id})).error,'NOT_FOUND');
 const waiter=f.tool('oa','rian_v2_job_status',{job_id:s.job_id,wait_seconds:5});
 await new Promise(r=>setTimeout(r,300));
 const done=await f.agentCall('aa','/v2/agent/jobs/'+job.jobId+'/complete',{leaseToken:job.leaseToken,outcome:'SUCCEEDED',exitCode:0,output:JSON.stringify({ok:true,waited_seconds:30})});
 assert.equal(done.body.state,'SUCCEEDED');
 const final=await waiter;
 assert.equal(final.state,'SUCCEEDED','long-poll returns as soon as the state changes');
 assert.equal(final.result.waited_seconds,30);
 const again=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'diag.wait',params:{seconds:30},request_key:'req-x'});
 assert.equal(again.error,'INVALID_REQUEST_KEY');
});

test('mail.read always needs its own approval; send/delete kinds do not exist',async t=>{
 const f=fixture(t);
 const r=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.read',params:{messageId:'c'.repeat(40)}});
 const p=await f.approvePage(r.job_id);
 assert.match(p.html,/1건/);assert.match(p.html,/반복 승인 대상이 아니며/);
 assert.equal((await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.send',params:{}})).error,'UNKNOWN_JOB_KIND');
 assert.equal((await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.sync',params:{days:180,maxMessages:3000}})).error,'MAIL_SCOPE_DENIED');
 assert.equal((await f.tool('oa','rian_v2_start_job',{device:'pcB',kind:'diag.wait',params:{seconds:1}})).error,'NOT_FOUND','tenant A cannot target tenant B PC');
 assert.equal((await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'diag.wait',params:{seconds:1},argv:['cmd']})).error,'INVALID_ARGUMENTS');
});

test('client reference digest matches the gateway formula and never carries the raw client id',()=>{
 const ref=clientRefFor('rian.client-id-example');
 assert.match(ref,/^[a-f0-9]{32}$/);
 assert.equal(ref,createHash('sha256').update('rian-v2-client|rian.client-id-example').digest('hex').slice(0,32));
});

test('spoofed X-Forwarded-For cannot bypass the per-job password attempt limit',async t=>{
 const f=fixture(t);
 const s=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'diag.wait',params:{seconds:4}});
 const {ticket}=await f.approvePage(s.job_id);
 const post=(ip,password)=>f.handler(new Request(ORIGIN+'/v2/approve/'+s.job_id,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',origin:ORIGIN,'x-forwarded-for':ip},body:new URLSearchParams({ticket,password}).toString()}));
 for(let i=0;i<10;i++)await post('10.0.0.'+i,'wrong-password-but-long-enough');
 assert.equal((await post('10.9.9.9',f.pwA)).status,429);
});
