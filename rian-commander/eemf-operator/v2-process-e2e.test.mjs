/**
 * Real-process E2E (Windows and Linux): staging service + OAuth Owner Gateway +
 * Python V2 agent as separate OS processes over loopback HTTP. Synthetic tenants,
 * synthetic mailbox, temporary directories only. No production endpoint, device,
 * credential or mailbox is touched.
 *
 * Proves: OAuth -> MCP start -> browser-password approval -> > 28 s job with
 * progress -> staging server hard kill + restart -> agent hard kill + restart ->
 * result collected exactly once; duplicate prevention; tenant A/B isolation;
 * 120-day index kept + 14-day merge; one approved mail-review grant covers
 * varied searches, recent/pending metadata and one selected body read.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync,readFileSync,existsSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {DatabaseSync} from 'node:sqlite';
import {hashApprovalPassword} from './long-job-http.mjs';

const HERE=fileURLToPath(new URL('.',import.meta.url));
const PYTHON=process.env.PYTHON||(process.platform==='win32'?'python':'python3');
const sha=b=>createHash('sha256').update(b).digest('hex');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const t0=Date.now();
const mark=(...a)=>console.log('[E2E +'+((Date.now()-t0)/1000).toFixed(1)+'s]',...a);
const freePort=()=>new Promise((res,rej)=>{const s=createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>res(p));});s.on('error',rej);});
const children=new Set();

function launch(name,cmd,args,env){
  const p=spawn(cmd,args,{cwd:HERE,env:{...process.env,...env},stdio:['ignore','pipe','pipe'],windowsHide:true});
  p.lines=[];p.name=name;children.add(p);
  const take=buf=>{for(const l of buf.toString('utf8').split(/\r?\n/))if(l.trim())p.lines.push(l);};
  p.stdout.on('data',take);p.stderr.on('data',take);
  p.on('exit',()=>children.delete(p));
  return p;
}
async function waitLine(p,re,ms=20000){
  const end=Date.now()+ms;
  while(Date.now()<end){const hit=p.lines.find(l=>re.test(l));if(hit)return hit;if(p.exitCode!==null)break;await sleep(100);}
  throw Error(p.name+' did not print '+re+'\n'+p.lines.slice(-20).join('\n'));
}
async function hardKill(p){
  if(p.exitCode!==null)return;
  const gone=new Promise(r=>p.once('exit',r));
  p.kill('SIGKILL');   // TerminateProcess on Windows: no graceful shutdown, simulates a crash
  await gone;
}

test('V2 long-running jobs across real processes with crash/restart, OAuth and mail',{timeout:420000},async t=>{
  const dir=mkdtempSync(join(tmpdir(),'rian-v2-e2e-'));
  t.after(async()=>{for(const c of [...children])await hardKill(c);await sleep(500);rmSync(dir,{recursive:true,force:true,maxRetries:5});});
  const port=await freePort(),gport=await freePort();
  const relay='http://127.0.0.1:'+port;
  const tokens=Object.fromEntries(['oa','ob','aa','ab'].map(k=>[k,randomBytes(40).toString('base64url')]));
  const pwA='e2e-owner-A-'+randomBytes(8).toString('hex'),pwB='e2e-owner-B-'+randomBytes(8).toString('hex');
  const principals=[['oa','A','owner'],['ob','B','owner'],['aa','A','agent','E2E-PC-A'],['ab','B','agent','E2E-PC-B']]
    .map(([id,tenantId,kind,deviceId])=>({id,tenantId,kind,...(deviceId?{deviceId}:{}),tokenSha256:sha(tokens[id])}));
  const serverEnv={RIAN_V2_E2E:'1',PORT:String(port),RIAN_E2E_DB_PATH:join(dir,'staging.db'),RIAN_STAGE_STORAGE_KEY:randomBytes(32).toString('hex'),
    RIAN_STAGE_JOBS_ENABLED:'1',RIAN_STAGE_ALLOW_DIAGNOSTICS:'1',RIAN_STAGE_MAIL_REVIEW_TOOLS:'1',RIAN_STAGE_PUBLIC_URL:relay,RIAN_STAGE_FORM_SECRET:randomBytes(48).toString('hex'),
    RIAN_STAGE_PRINCIPALS_JSON:JSON.stringify(principals),RIAN_STAGE_DEVICES_JSON:JSON.stringify([{id:'E2E-PC-A',tenantId:'A',allowedKinds:['diag.wait','mail.sync','mail.search','mail.read','mail.status','mail.recent','mail.review_pending']},{id:'E2E-PC-B',tenantId:'B'}]),
    RIAN_STAGE_APPROVERS_JSON:JSON.stringify([{tenantId:'A',ownerId:'oa',...hashApprovalPassword(pwA)},{tenantId:'B',ownerId:'ob',...hashApprovalPassword(pwB)}])};
  const startServer=async()=>{const s=launch('staging','node',['v2-e2e-server.mjs'],serverEnv);await waitLine(s,/RIAN_V2_E2E_READY/);return s;};
  let server=await startServer();
  mark('staging service up on',relay);

  // Synthetic mailbox: 120-day legacy index (no bodies) + 14 days of "new" mail incl. overlap.
  const NOW=Date.now(),day=86400000,msg=(p,d,k)=>({message_id:`<${p}-${d}-${k}@e2e.test>`,date:new Date(NOW-d*day-k*3600000).toISOString(),from:`s${k}@e2e.test`,subject:`E2E 합성 견적 ${p}-${d}-${k}`,body:`SYNTHETIC BODY ${p}-${d}-${k}`});
  const legacy=[];for(let d=0;d<120;d++)for(let k=0;k<2;k++)legacy.push(msg('old',d,k));
  const recent=[];for(let d=0;d<14;d++)for(let k=0;k<2;k++)recent.push(msg('old',d,k));for(let d=0;d<3;d++)for(let k=0;k<4;k++)recent.push(msg('new',d,k));
  writeFileSync(join(dir,'legacy-index.json'),JSON.stringify({account:'e2e.user@example.test',messages:legacy.map(({body,...m})=>m)}));
  writeFileSync(join(dir,'mailbox.json'),JSON.stringify({account:'e2e.user@example.test',messages:recent}));
  const agentCfg=join(dir,'agentA.json');
  writeFileSync(join(dir,'agentA.token'),tokens.aa);
  writeFileSync(agentCfg,JSON.stringify({relay_url:relay,device_id:'E2E-PC-A',token_file:join(dir,'agentA.token'),state_dir:join(dir,'agentA-state'),
    allowed_kinds:['diag.wait','mail.status','mail.sync','mail.search','mail.read','mail.recent','mail.review_pending'],allow_test_loopback:true,poll_seconds:1,
    mail:{data_dir:join(dir,'rian-mail-v2'),account_fingerprint:sha('rian-mail-account-v2|e2e.user@example.test'),legacy_index:join(dir,'legacy-index.json'),source:{type:'fixture',path:join(dir,'mailbox.json')}}}));
  const startAgent=async()=>{const a=launch('agentA',PYTHON,['rian-v2-agent.py','run','--config',agentCfg],{});await waitLine(a,/AGENT_STARTED/);return a;};

  // ---- OAuth Owner Gateway (real gateway.ts) --------------------------------------------------
  const gwOrigin='https://gateway.e2e.test',gw='http://127.0.0.1:'+gport,ownerPw='e2e-gateway-owner-'+randomBytes(10).toString('hex');
  const gateway=launch('gateway','node',['v2-e2e-gateway.mjs'],{RIAN_V2_E2E:'1',PORT:String(gport),RIAN_GATEWAY_PUBLIC_URL:gwOrigin,
    RIAN_OAUTH_SIGNING_SECRET:randomBytes(48).toString('base64url'),RIAN_OWNER_PASSWORD:ownerPw,RIAN_V2_MCP_URL:relay+'/v2/mcp',
    RIAN_V2_OWNER_TOKEN:tokens.oa,RIAN_V2_ALLOW_LOOPBACK:'1',RIAN_EEMF_BACKEND_URL:'',RIAN_EEMF_GATEWAY_TOKEN:'',RIAN_EEMF_APPROVAL_SECRET:''});
  await waitLine(gateway,/RIAN_V2_E2E_GATEWAY_READY/);
  const health=await (await fetch(gw+'/health')).json();
  assert.equal(health.v2_jobs,true);assert.equal(health.backend_configured,false,'legacy relay not configured in E2E');
  const reg=await (await fetch(gw+'/oauth/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({redirect_uris:['http://127.0.0.1/callback'],token_endpoint_auth_method:'none'})})).json();
  const verifier=randomBytes(48).toString('base64url'),challenge=createHash('sha256').update(verifier).digest('base64url');
  const q=new URLSearchParams({client_id:reg.client_id,redirect_uri:'http://127.0.0.1/callback',response_type:'code',scope:'eemf:operate offline_access',code_challenge:challenge,code_challenge_method:'S256',resource:gwOrigin+'/mcp',state:'e2e'});
  const loginHtml=await (await fetch(gw+'/oauth/authorize?'+q)).text();
  const request=/name="request" value="([^"]+)"/.exec(loginHtml)[1].replaceAll('&amp;','&');
  const approve=await fetch(gw+'/oauth/approve',{method:'POST',redirect:'manual',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({request,password:ownerPw})});
  assert.equal(approve.status,302);
  const code=new URL(approve.headers.get('location')).searchParams.get('code');
  const tok=await (await fetch(gw+'/oauth/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',code,code_verifier:verifier,client_id:reg.client_id,redirect_uri:'http://127.0.0.1/callback',resource:gwOrigin+'/mcp'})})).json();
  assert.ok(tok.access_token);
  mark('OAuth authorization_code + PKCE completed against real gateway.ts');
  let rid=0;
  const mcp=async(method,params,bearer=tok.access_token,url=gw+'/mcp')=>{
    const r=await fetch(url,{method:'POST',headers:{authorization:'Bearer '+bearer,'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:++rid,method,params})});
    return {status:r.status,body:r.status===200?await r.json():null};
  };
  const call=async(name,args,bearer,url)=>{const {status,body}=await mcp('tools/call',{name,arguments:args},bearer,url);assert.equal(status,200);const x=body.result.content[0].text;return body.result.isError?{error:x}:JSON.parse(x);};
  assert.equal((await mcp('tools/list',{},'not-a-token')).status,401,'gateway requires OAuth');
  const names=(await mcp('tools/list',{})).body.result.tools.map(x=>x.name);
  assert.ok(names.includes('rian_v2_start_job')&&names.includes('rian_v2_job_status')&&
    ['mail_status','mail_sync','mail_search','mail_read','mail_recent','mail_review_pending'].every(n=>names.includes(n)),'V2 mail tools exposed through OAuth gateway');
  assert.ok(!names.some(n=>/approve/.test(n)));

  const browserApprove=async(approvalUrl,password,extra={})=>{
    const html=await (await fetch(approvalUrl)).text();
    const ticket=/name="ticket" value="([^"]+)"/.exec(html)[1];
    const r=await fetch(approvalUrl,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',origin:relay},body:new URLSearchParams({ticket,password,...extra})});
    return {status:r.status,html:await r.text(),preview:html};
  };
  const waitState=async(jobId,states,ms=150000)=>{
    const end=Date.now()+ms;let s;
    while(Date.now()<end){
      try{s=await call('rian_v2_job_status',{job_id:jobId,wait_seconds:5});}catch{await sleep(1000);continue;}
      if(s.error){await sleep(1000);continue;}
      if(states.includes(s.state))return s;
    }
    throw Error('timeout waiting for '+states+' last='+JSON.stringify(s));
  };

  // ---- A: 40 s job through ChatGPT-equivalent MCP calls ----------------------------------------
  let agent=await startAgent();
  const devices=await call('rian_v2_devices',{});
  assert.deepEqual(devices.devices.map(d=>d.device),['E2E-PC-A'],'tenant A sees only its PC');
  const started=await call('rian_v2_start_job',{device:'E2E-PC-A',kind:'diag.wait',params:{seconds:40},request_key:'e2e-long-job-0001'});
  assert.equal(started.state,'AWAITING_APPROVAL');
  mark('job requested, id returned immediately',started.job_id);
  const ok=await browserApprove(started.approval_url,pwA);
  assert.equal(ok.status,200);
  const running=await waitState(started.job_id,['RUNNING']);
  mark('RUNNING on agent; progress',JSON.stringify(running.progress));
  const dup=await call('rian_v2_start_job',{device:'E2E-PC-A',kind:'diag.wait',params:{seconds:40}});
  assert.equal(dup.job_id,started.job_id);assert.equal(dup.deduplicated,true);
  const dupKey=await call('rian_v2_start_job',{device:'E2E-PC-A',kind:'diag.wait',params:{seconds:40},request_key:'e2e-long-job-0001'});
  assert.equal(dupKey.job_id,started.job_id);
  const conflict=await call('rian_v2_start_job',{device:'E2E-PC-A',kind:'diag.wait',params:{seconds:41}});
  assert.match(conflict.error,new RegExp('ACTIVE_JOB_CONFLICT:'+started.job_id));
  // Tenant B, talking to the staging MCP with its own owner token, cannot see or cancel A's job.
  const bView=await call('rian_v2_job_status',{job_id:started.job_id},tokens.ob,relay+'/v2/mcp');
  assert.equal(bView.error,'NOT_FOUND');
  assert.equal((await call('rian_v2_cancel_job',{job_id:started.job_id},tokens.ob,relay+'/v2/mcp')).error,'NOT_FOUND');
  assert.equal((await call('rian_v2_start_job',{device:'E2E-PC-A',kind:'diag.wait',params:{seconds:2}},tokens.ob,relay+'/v2/mcp')).error,'NOT_FOUND');
  const bDevices=await call('rian_v2_devices',{},tokens.ob,relay+'/v2/mcp');
  assert.deepEqual(bDevices.devices.map(d=>d.device),['E2E-PC-B']);
  mark('duplicate prevention and tenant isolation verified while running');

  await sleep(6000);
  await hardKill(server);
  mark('staging service HARD-KILLED mid-run');
  await sleep(6000);
  server=await startServer();
  const recovered=await waitLine(server,/RIAN_STAGING_LONG_JOBS_RECOVERED/);
  assert.match(recovered,/"runningPreserved":1/);
  mark('staging service restarted:',recovered.replace(/^.*RECOVERED /,''));
  await sleep(4000);
  await hardKill(agent);
  mark('agent supervisor HARD-KILLED mid-run (runner keeps working)');
  await sleep(3000);
  agent=await startAgent();
  assert.match(agent.lines.find(l=>/AGENT_STARTED/.test(l)),/"recovered": 1/);
  mark('agent restarted and recovered its journal');
  const finished=await waitState(started.job_id,['SUCCEEDED','FAILED','UNKNOWN_DO_NOT_RETRY','INTERRUPTED']);
  assert.equal(finished.state,'SUCCEEDED',JSON.stringify(finished));
  assert.equal(finished.result.waited_seconds,40);
  assert.ok(finished.finished_at-finished.started_at>=40,'ran longer than the legacy 28 s synchronous window');
  mark('SUCCEEDED; duration',finished.finished_at-finished.started_at,'s; result',JSON.stringify(finished.result));
  const db=new DatabaseSync(serverEnv.RIAN_E2E_DB_PATH,{readOnly:true});
  const events=db.prepare('SELECT action FROM audit WHERE object_id=? ORDER BY id').all(started.job_id).map(r=>r.action);
  db.close();
  assert.equal(events.filter(e=>e==='LONG_JOB_DISPATCHED').length,1,'dispatched exactly once across both restarts');
  assert.ok(events.includes('LONG_JOB_LEASE_RESTART_GRACE'));
  const executed=JSON.parse(readFileSync(join(dir,'agentA-state','executed-job-ids.json'),'utf8'));
  assert.equal(executed.filter(x=>x===started.job_id).length,1);
  mark('audit:',events.join(' > '));

  // ---- C: one browser approval across the read-only mail workflow ---------------------------
  const sync1=await call('mail_sync',{device:'E2E-PC-A',days:14,max_messages:1000});
  const sApprove=await browserApprove(sync1.approval_url,pwA,{review:'1',review_minutes:'60',review_jobs:'10',review_body:'1',review_reads:'2'});
  assert.match(sApprove.preview,/최근 14일, 최대 1000건/);assert.equal(sApprove.status,200);
  const s1=await waitState(sync1.job_id,['SUCCEEDED','FAILED']);
  assert.equal(s1.state,'SUCCEEDED',JSON.stringify(s1));
  assert.deepEqual([s1.result.legacy_seeded,s1.result.added,s1.result.unchanged,s1.result.total,s1.result.removed],[240,12,28,252,0]);
  mark('mail.sync #1: 120-day legacy index kept (240) + 14-day merge, total',s1.result.total);
  const sync2=await call('mail_sync',{device:'E2E-PC-A',days:14,max_messages:1000});
  assert.equal(sync2.state,'QUEUED','mail review: no second password');assert.equal(sync2.approval_url,undefined);
  const s2=await waitState(sync2.job_id,['SUCCEEDED','FAILED']);
  assert.deepEqual([s2.result.added,s2.result.total,s2.result.before],[0,252,252]);
  assert.ok(s2.result.backup&&existsSync(join(dir,'rian-mail-v2','backups',s2.result.backup)),'previous index backed up before write');
  mark('mail.sync #2 via review grant without password: added 0, total 252, backup',s2.result.backup);
  const status=await call('mail_status',{device:'E2E-PC-A'});
  assert.equal(status.state,'QUEUED');
  const st=await waitState(status.job_id,['SUCCEEDED','FAILED']);
  assert.equal(st.result.messages,252);assert.ok(st.result.synced_at);
  const recentJob=await call('mail_recent',{device:'E2E-PC-A',days:14,limit:5,offset:0});
  assert.equal(recentJob.state,'QUEUED');
  const recentResult=await waitState(recentJob.job_id,['SUCCEEDED','FAILED']);
  assert.equal(recentResult.result.results.length,5);assert.equal(recentResult.result.next_offset,5);
  const search=await call('mail_search',{device:'E2E-PC-A',query:'new-1-2',limit:5,offset:0});
  assert.equal(search.state,'QUEUED');assert.equal(search.approval_url,undefined);
  const sr=await waitState(search.job_id,['SUCCEEDED','FAILED']);
  assert.equal(sr.result.count,1);assert.equal(sr.result.bodies_included,false);
  assert.ok(!JSON.stringify(sr.result).includes('SYNTHETIC BODY'));
  const messageId=sr.result.results[0].message_id;
  const read=await call('mail_read',{device:'E2E-PC-A',message_id:messageId});
  assert.equal(read.state,'QUEUED','a searched recent body uses the explicit review consent');
  assert.equal(read.approval_url,undefined);
  const rr=await waitState(read.job_id,['SUCCEEDED','FAILED']);
  assert.equal(rr.result.messages_returned,1);
  assert.equal(rr.result.body,'SYNTHETIC BODY new-1-2');
  const changed=await call('mail_search',{device:'E2E-PC-A',query:'new-2',limit:5});
  assert.equal(changed.state,'QUEUED','different search query uses the same approval');
  const changedResult=await waitState(changed.job_id,['SUCCEEDED','FAILED']);
  assert.equal(changedResult.result.count,4);
  const pending=await call('mail_review_pending',{device:'E2E-PC-A',days:14,limit:5});
  assert.equal(pending.state,'QUEUED');
  const pendingResult=await waitState(pending.job_id,['SUCCEEDED','FAILED']);
  assert.equal(pendingResult.result.sent_folder_indexed,false);
  assert.equal(pendingResult.result.results[0].reply_check,'SENT_NOT_INDEXED');
  mark('one approval covered sync, status, recent, varied searches, selected read and pending review');
  const grants=await call('rian_v2_list_grants',{});
  assert.equal(grants.grants.length,1);assert.equal(grants.grants[0].runs_left,3,'seven of ten approved follow-up jobs used');
  assert.equal((await call('rian_v2_revoke_grant',{grant_id:grants.grants[0].grant_id})).state,'REVOKED');
  const sync3=await call('mail_sync',{device:'E2E-PC-A',days:14,max_messages:1000});
  assert.equal(sync3.state,'AWAITING_APPROVAL','revoked grant no longer skips approval');
  assert.equal((await call('rian_v2_cancel_job',{job_id:sync3.job_id})).state,'APPROVAL_CANCELLED');
  mark('mail review grant revoked; approval required again; pending approval cancelled');
});
