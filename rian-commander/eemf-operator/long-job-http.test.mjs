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
import {createLongJobHandler,hashApprovalPassword,clientRefFor} from './long-job-http.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const ORIGIN='https://rian-commander-tenant-staging.example.test';
function fixture(t,clock=()=>Date.now()){
 const dir=mkdtempSync(join(tmpdir(),'rian-ljhttp-'));
 const tkn=Object.fromEntries(['oa','oa2','ob','aa','ab'].map(x=>[x,randomBytes(40).toString('base64url')]));
 const directory=new TenantDirectory({devices:[{id:'pcA',tenantId:'A'},{id:'pcB',tenantId:'B'}],
  principals:[['oa','A','owner'],['oa2','A','owner'],['ob','B','owner'],['aa','A','agent','pcA'],['ab','B','agent','pcB']]
   .map(([id,tenantId,kind,deviceId])=>({id,tenantId,kind,...(deviceId?{deviceId}:{}),tokenSha256:sha(tkn[id])}))});
 const store=new StagingSqlite({filename:join(dir,'s.db'),encryptionKeyHex:randomBytes(32).toString('hex')});
 const queue=new LongJobQueue({directory,store,clock,kinds:new LongJobKinds({allowDiagnostics:true,allowMailReviewTools:true}),
  deviceKinds:{pcA:['diag.wait','mail.sync','mail.search','mail.read','mail.status','mail.recent','mail.review_pending']}});
 const pwA='synthetic-owner-A-password-'+randomBytes(4).toString('hex'),pwB='synthetic-owner-B-password-'+randomBytes(4).toString('hex');
 const approvers=[{tenantId:'A',ownerId:'oa',...hashApprovalPassword(pwA)},{tenantId:'B',ownerId:'ob',...hashApprovalPassword(pwB)}];
 const handler=createLongJobHandler({directory,queue,approvers,publicOrigin:ORIGIN,formSecret:randomBytes(48).toString('hex'),clock});
 t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
 const rpc=async(who,method,params={},extra={})=>{
  const r=await handler(new Request(ORIGIN+'/v2/mcp',{method:'POST',headers:{authorization:'Bearer '+tkn[who],'content-type':'application/json',...extra},body:JSON.stringify({jsonrpc:'2.0',id:7,method,params})}));
  return {status:r.status,body:r.status===202?null:await r.json()};
 };
 const tool=async(who,name,args,headers={})=>{
  const {body}=await rpc(who,'tools/call',{name,arguments:args},headers);
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
 assert.deepEqual(names,['mail_status','mail_sync','mail_search','mail_read','mail_recent','mail_review_pending',
   'rian_v2_devices','rian_v2_start_job','rian_v2_job_status','rian_v2_list_jobs','rian_v2_cancel_job','rian_v2_list_grants','rian_v2_revoke_grant']);
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

test('ChatGPT approval link tracking parameter opens only the read-only preview',async t=>{
 const f=fixture(t);
 const job=await f.tool('oa','mail_sync',{device:'pcA',days:14,max_messages:100});
 const path=ORIGIN+'/v2/approve/'+job.job_id;
 const preview=await f.handler(new Request(path+'?utm_source=chatgpt.com'));
 assert.equal(preview.status,200);
 assert.match(await preview.text(),/업무메일 연속 검토|업무메일 색인 동기화/);
 for(const query of ['?utm_source=other','?utm_source=chatgpt.com&utm_source=chatgpt.com','?utm_source=chatgpt.com&scope=extra']){
  assert.equal((await f.handler(new Request(path+query))).status,404);
 }
 assert.equal((await f.handler(new Request(path+'?utm_source=chatgpt.com',{method:'POST'}))).status,404);
});

test('dedicated mail tools map to bounded jobs and preserve approval requirements',async t=>{
 const f=fixture(t);
 const sync=await f.tool('oa','mail_sync',{device:'pcA',days:14,max_messages:100});
 assert.equal(sync.kind,'mail.sync');assert.equal(sync.state,'AWAITING_APPROVAL');
 await f.tool('oa','rian_v2_cancel_job',{job_id:sync.job_id});
 const search=await f.tool('oa','mail_search',{device:'pcA',query:'견적',limit:5,offset:10,sender:'sender@example.test'});
 assert.equal(search.kind,'mail.search');assert.equal(search.params.offset,10);
 assert.equal(search.state,'AWAITING_APPROVAL');
 await f.tool('oa','rian_v2_cancel_job',{job_id:search.job_id});
 const recent=await f.tool('oa','mail_recent',{device:'pcA',days:7,limit:10});
 assert.equal(recent.kind,'mail.recent');assert.equal(recent.state,'AWAITING_APPROVAL');
 await f.tool('oa','rian_v2_cancel_job',{job_id:recent.job_id});
 const status=await f.tool('oa','mail_status',{device:'pcA'});
 assert.equal(status.kind,'mail.status');
 await f.tool('oa','rian_v2_cancel_job',{job_id:status.job_id});
 const pending=await f.tool('oa','mail_review_pending',{device:'pcA',days:7});
 assert.equal(pending.kind,'mail.review_pending');
 await f.tool('oa','rian_v2_cancel_job',{job_id:pending.job_id});
 const read=await f.tool('oa','mail_read',{device:'pcA',message_id:'a'.repeat(40)});
 assert.equal(read.kind,'mail.read');assert.equal(read.state,'AWAITING_APPROVAL');
 assert.ok((await f.tool('oa','mail_search',{device:'pcA',query:'--all'})).error);
 assert.ok((await f.tool('ob','mail_status',{device:'pcA'})).error,'cross-tenant device denied');
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
 assert.equal(ok.status,200);
 const single=await ok.text();
 assert.match(single,/이번 작업 1건 승인 완료/);
 assert.match(single,/연속 권한은 생성되지 않았습니다/);
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
 assert.equal(ok.status,200);assert.match(ok.html,/동일 작업 반복 승인 완료/);
 assert.match(ok.html,/grant_id:/);assert.match(ok.html,/남은 호출: 3/);assert.match(ok.html,/권한 상태: ACTIVE/);
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

test('an expired unexecuted request can be approved at its original link with a new ticket and owner password',async t=>{
 let now=Date.now();const f=fixture(t,()=>now),oauth={'x-rian-client-ref':'a'.repeat(32)};
 const job=await f.tool('oa','mail_sync',{device:'pcA',days:14,max_messages:1000},oauth);
 const original=await f.approvePage(job.job_id);
 now+=901000;
 const renewed=await f.approvePage(job.job_id);
 assert.equal(renewed.status,200);
 assert.match(renewed.html,/같은 링크에서 소유자 암호로 다시 승인/);
 assert.equal((await f.tool('oa','rian_v2_job_status',{job_id:job.job_id})).state,'APPROVAL_EXPIRED');
 const stale=await f.submit(job.job_id,{ticket:original.ticket,password:f.pwA,review:'1'});
 assert.match(stale.html,/양식이 만료/);
 const wrong=await f.submit(job.job_id,{ticket:renewed.ticket,password:'incorrect-owner-password',review:'1',
   review_minutes:'30',review_jobs:'10'});
 assert.match(wrong.html,/name="review" value="1"[^>]* checked/);
 const ticket=/name="ticket" value="([^"]+)"/.exec(wrong.html)?.[1];
 const approved=await f.submit(job.job_id,{ticket,password:f.pwA,review:'1',review_minutes:'30',review_jobs:'10'});
 assert.match(approved.html,/업무메일 연속 검토 승인 완료/);
 assert.equal((await f.tool('oa','rian_v2_job_status',{job_id:job.job_id})).state,'QUEUED');
 assert.equal((await f.tool('oa','rian_v2_list_grants',{})).grants[0].state,'PENDING_SYNC');
});

test('password error preserves the selected mail review scope without echoing the password',async t=>{
 const f=fixture(t),oauth={'x-rian-client-ref':'a'.repeat(32)};
 const job=await f.tool('oa','mail_sync',{device:'pcA',days:14,max_messages:1000},oauth);
 const p=await f.approvePage(job.job_id);
 const bad=await f.submit(job.job_id,{ticket:p.ticket,password:'incorrect-owner-password',review:'1',
   review_minutes:'30',review_jobs:'10',review_body:'1',review_reads:'1'});
 assert.match(bad.html,/승인 암호가 일치하지 않습니다/);
 assert.match(bad.html,/name="review" value="1"[^>]* checked/);
 assert.match(bad.html,/name="review_body" value="1"[^>]* checked/);
 assert.match(bad.html,/id="review_jobs"[^>]*value="10"/);
 assert.match(bad.html,/id="review_reads"[^>]*value="1"/);
 assert.doesNotMatch(bad.html,/incorrect-owner-password/);
 const newTicket=/name="ticket" value="([^"]+)"/.exec(bad.html)?.[1];
 const ok=await f.submit(job.job_id,{ticket:newTicket,password:f.pwA,review:'1',
   review_minutes:'30',review_jobs:'10',review_body:'1',review_reads:'1'});
 assert.match(ok.html,/업무메일 연속 검토 승인 완료/);
 assert.match(ok.html,/남은 본문 조회: 1/);
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
 assert.equal((await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.send',params:{}})).error,'KIND_NOT_ALLOWED_FOR_DEVICE');
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


test('mail-review: one browser approval permits multiple different searches and selected recent bodies',async t=>{
 const f=fixture(t),oauthA={'x-rian-client-ref':'a'.repeat(32)},oauthOther={'x-rian-client-ref':'b'.repeat(32)};
 const sync=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.sync',params:{days:14,maxMessages:108}},oauthA);
 assert.equal(sync.state,'AWAITING_APPROVAL');
 const form=await f.approvePage(sync.job_id);
 assert.match(form.html,/업무메일 연속 검토/);
 assert.match(form.html,/최근 지정 기간의 메일/);
 const approved=await f.submit(sync.job_id,{ticket:form.ticket,password:f.pwA,review:'1',
   review_minutes:'60',review_jobs:'8',review_body:'1',review_reads:'2'});
 assert.equal(approved.status,200);
 assert.match(approved.html,/업무메일 연속 검토 승인 완료/);
 assert.match(approved.html,/권한 상태: PENDING_SYNC/);
 assert.match(approved.html,/남은 호출: 8/);
 const active=await f.tool('oa','rian_v2_list_grants',{});
 assert.equal(active.grants.length,1);
 const review=active.grants[0];
 assert.equal(review.kind,'mail.review.readonly');
 assert.equal(review.state,'PENDING_SYNC');
 assert.equal(review.runs_left,8);assert.equal(review.body_reads_left,2);
 const premature=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.search',params:{query:'동기화 전',limit:2}},oauthA);
 assert.equal(premature.state,'AWAITING_APPROVAL','a review grant must not work before the initial sync succeeds');
 // Local agent consumes the approved initial read-only sync job.
 const sc=(await f.agentCall('aa','/v2/agent/claim',{deviceId:'pcA'})).body.job;
 assert.equal(sc.jobId,sync.job_id);
 await f.agentCall('aa','/v2/agent/jobs/'+sc.jobId+'/complete',{leaseToken:sc.leaseToken,
   outcome:'SUCCEEDED',exitCode:0,output:JSON.stringify({ok:true,account_match:true,mailbox_modified:false,added:108})});
 assert.equal((await f.tool('oa','rian_v2_list_grants',{})).grants[0].state,'ACTIVE');
 const recent='c'.repeat(40),old='d'.repeat(40);
 const search=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.search',params:{query:'장애',limit:20}},oauthA);
 assert.equal(search.state,'QUEUED');assert.equal(search.approval_required,false);
 assert.equal(search.via_mail_review_session,true);
 const work=(await f.agentCall('aa','/v2/agent/claim',{deviceId:'pcA'})).body.job;
 assert.equal(work.jobId,search.job_id);
 await f.agentCall('aa','/v2/agent/jobs/'+work.jobId+'/complete',{leaseToken:work.leaseToken,outcome:'SUCCEEDED',exitCode:0,
   output:JSON.stringify({ok:true,results:[
     {message_id:recent,date:new Date().toISOString(),subject:'장애',from:'example.invalid'},
     {message_id:old,date:'2020-01-01T00:00:00Z',subject:'옛 장애',from:'example.invalid'}
   ],bodies_included:false})});
 const read=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.read',params:{messageId:recent}},oauthA);
 assert.equal(read.state,'QUEUED');assert.equal(read.approval_required,false);
 assert.equal(read.via_mail_review_session,true);
 // A different OAuth client, older message, and unused address cannot inherit the grant.
 const otherClient=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.read',params:{messageId:old}},oauthOther);
 assert.equal(otherClient.state,'AWAITING_APPROVAL');
 const ancient=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.read',params:{messageId:old}},oauthA);
 assert.match(ancient.error,/ACTIVE_JOB_CONFLICT/,'a different OAuth client cannot deduplicate another pending request');
 assert.equal((await f.tool('ob','rian_v2_list_grants',{})).grants.length,0);
 const second=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.search',params:{query:'정기점검',limit:8}},oauthA);
 assert.equal(second.state,'QUEUED','changed query reuses the same single owner approval');
 const remaining=(await f.tool('oa','rian_v2_list_grants',{})).grants[0];
 assert.equal(remaining.runs_left,5);
 assert.equal(remaining.body_reads_left,1);
 // Revoking a review session stops all its queued jobs before claim.
 const revoked=await f.tool('oa','rian_v2_revoke_grant',{grant_id:review.grant_id});
 assert.equal(revoked.state,'REVOKED');
 assert.equal((await f.tool('oa','rian_v2_job_status',{job_id:second.job_id})).state,'CANCELLED');
 assert.equal((await f.tool('oa','rian_v2_job_status',{job_id:read.job_id})).state,'CANCELLED');
 assert.equal((await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.search',params:{query:'새 요청',limit:2}},oauthA)).state,'AWAITING_APPROVAL');
 assert.equal((await f.tool('oa','rian_v2_list_grants',{})).grants.length,0);
});

test('mail-review: failed initial sync revokes the pending review scope',async t=>{
 const f=fixture(t),oauth={'x-rian-client-ref':'c'.repeat(32)};
 const sync=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.sync',params:{days:14,maxMessages:100}},oauth);
 const form=await f.approvePage(sync.job_id);
 assert.equal((await f.submit(sync.job_id,{ticket:form.ticket,password:f.pwA,review:'1',
   review_minutes:'60',review_jobs:'10',review_body:'1',review_reads:'2'})).status,200);
 const claim=(await f.agentCall('aa','/v2/agent/claim',{deviceId:'pcA'})).body.job;
 await f.agentCall('aa','/v2/agent/jobs/'+claim.jobId+'/complete',{leaseToken:claim.leaseToken,
   outcome:'FAILED',exitCode:2,output:JSON.stringify({ok:false,error:'MAIL_CREDENTIALS_MISSING'})});
 assert.equal((await f.tool('oa','rian_v2_list_grants',{})).grants.length,0);
 const search=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.search',params:{query:'장애',limit:2}},oauth);
 assert.equal(search.state,'AWAITING_APPROVAL');
});

test('mail-review: original approval remains one-time without OAuth ref; review input is bounded',async t=>{
 const f=fixture(t);
 const one=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.sync',params:{days:14,maxMessages:100}});
 const page=await f.approvePage(one.job_id);
 assert.doesNotMatch(page.html,/업무메일 연속 검토/);
 assert.equal((await f.submit(one.job_id,{ticket:page.ticket,password:f.pwA,
   review:'1',review_minutes:'30',review_jobs:'10'})).status,400,'cannot grant to unbound caller');
 const withRef=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.sync',params:{days:14,maxMessages:100}},{
  'x-rian-client-ref':'b'.repeat(32)
 });
 // This is a duplicate active sync; it must not gain client ref by replay.
 assert.match(withRef.error,/ACTIVE_JOB_CONFLICT/,'a new OAuth client cannot inherit the existing unaffiliated sync job');
 const bad=await f.approvePage(one.job_id);
 assert.equal((await f.submit(one.job_id,{ticket:bad.ticket,password:f.pwA,
   standing:'1',review:'1'})).status,400);
});

test('mail-review scope policy: only bounded recent search hits authorize a body',async()=>{
 const {planMailReview,recentMessageHashes,reviewMessageHash,reviewAllows}=await import('./mail-review-scope.mjs');
 assert.throws(()=>planMailReview({initialKind:'mail.read',initialParams:{},clientRef:'a'.repeat(32)}),/INITIAL_SYNC/);
 assert.throws(()=>planMailReview({initialKind:'mail.sync',initialParams:{days:14,maxMessages:100},clientRef:'a'.repeat(32),minutes:61}),/SCOPE_INVALID/);
 const s=planMailReview({initialKind:'mail.sync',initialParams:{days:7,maxMessages:100},clientRef:'a'.repeat(32),bodyReads:2});
 assert.equal(s.bodyReads,2);
 const now=1762000000,fresh=new Date(now*1000).toISOString();
 const ids=recentMessageHashes({ok:true,results:[{message_id:'e'.repeat(40),date:fresh},
   {message_id:'f'.repeat(40),date:'2020-01-01T00:00:00Z'},
   {message_id:'g'.repeat(40),date:fresh}]},{nowSeconds:now,maxDays:7});
 assert.deepEqual(ids,[reviewMessageHash('e'.repeat(40))]);
 assert.equal(reviewAllows({state:'ACTIVE',runs_left:1,reads_left:2,max_days:7,max_messages:100},'mail.read',{messageId:'e'.repeat(40)},true),true);
 assert.equal(reviewAllows({state:'ACTIVE',runs_left:1,reads_left:2,max_days:7,max_messages:100},'mail.read',{messageId:'e'.repeat(40)},false),false);
});


test('mail-review: a different owner within the SAME tenant cannot list, view, cancel or deduplicate another owner job',async t=>{
 const f=fixture(t);
 const sync=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.sync',params:{days:14,maxMessages:100}},{
  'x-rian-client-ref':'a'.repeat(32)
 });
 assert.equal(sync.state,'AWAITING_APPROVAL');
 assert.equal((await f.tool('oa2','rian_v2_job_status',{job_id:sync.job_id})).error,'NOT_FOUND');
 assert.equal((await f.tool('oa2','rian_v2_cancel_job',{job_id:sync.job_id})).error,'NOT_FOUND');
 assert.deepEqual((await f.tool('oa2','rian_v2_list_jobs',{})).jobs,[]);
 const cl=await f.tool('oa2','rian_v2_start_job',{device:'pcA',kind:'mail.sync',params:{days:14,maxMessages:100}},{
  'x-rian-client-ref':'a'.repeat(32)
 });
 assert.equal(cl.error,'ACTIVE_JOB_CONFLICT','no foreign owner job id is returned');
 assert.equal((await f.tool('oa','rian_v2_job_status',{job_id:sync.job_id})).state,'AWAITING_APPROVAL');
 const otherOAuth=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.sync',params:{days:14,maxMessages:100}},{
  'x-rian-client-ref':'b'.repeat(32)
 });
 assert.match(otherOAuth.error,/ACTIVE_JOB_CONFLICT/,'a different OAuth client cannot inherit the active request');
});

test('mail-review: default metadata-only approval cannot read any message body without a separate per-message approval',async t=>{
 const f=fixture(t),ref={'x-rian-client-ref':'a'.repeat(32)};
 const sync=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.sync',params:{days:7,maxMessages:50}},ref);
 const page=await f.approvePage(sync.job_id);
 const approval=await f.submit(sync.job_id,{ticket:page.ticket,password:f.pwA,review:'1',
   review_minutes:'10',review_jobs:'4'});
 assert.equal(approval.status,200);
 const grant=(await f.tool('oa','rian_v2_list_grants',{})).grants[0];
 assert.equal(grant.body_reads_left,0);
 assert.equal(grant.state,'PENDING_SYNC');
 const searched=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.search',params:{query:'회의',limit:5}},ref);
 assert.equal(searched.state,'AWAITING_APPROVAL','review grant must not activate before successful sync');
 const read=await f.tool('oa','rian_v2_start_job',{device:'pcA',kind:'mail.read',params:{messageId:'a'.repeat(40)}},ref);
 assert.equal(read.state,'AWAITING_APPROVAL','no body permission in the original approval');
});
