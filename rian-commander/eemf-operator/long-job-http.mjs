/**
 * RIAN Commander V2 long-job HTTP surface for the isolated staging service.
 *
 *  POST /v2/mcp                         owner bearer (the OAuth Gateway holds it) - JSON-RPC MCP tools
 *  POST /v2/agent/claim                 device bearer - claim the next approved job for this device
 *  POST /v2/agent/jobs/<id>/heartbeat   device bearer + lease token - progress, cancel signal
 *  POST /v2/agent/jobs/<id>/complete    device bearer + lease token - encrypted result
 *  GET  /v2/approve/<id>                owner approval page (exact scope preview)
 *  POST /v2/approve/<id>                owner password -> QUEUED, optional exact-scope standing grant
 *
 * There is deliberately NO MCP tool that approves a job: approval needs the
 * tenant owner's password in a browser page served by this service.
 */
import {createHmac,randomBytes,scryptSync,timingSafeEqual,createHash} from 'node:crypto';
import {TenantDirectory} from './tenant-artifact-core.mjs';
import {LongJobQueue} from './durable-long-jobs.mjs';

const MAX_BODY=110_000;
const JSON_HEADERS={'cache-control':'no-store','content-type':'application/json; charset=utf-8','x-content-type-options':'nosniff'};
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:JSON_HEADERS});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const escapeHtml=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function readBody(request,max=MAX_BODY){
  const reader=request.body?.getReader();
  if(!reader)return Buffer.alloc(0);
  const chunks=[];let len=0;
  try{
    for(;;){const {done,value}=await reader.read();if(done)break;len+=value.byteLength;if(len>max){await reader.cancel();throw Error('BODY_TOO_LARGE');}chunks.push(value);}
  }finally{reader.releaseLock();}
  return Buffer.concat(chunks);
}
async function jsonBody(request){
  if(request.headers.get('content-type')?.split(';')[0].trim().toLowerCase()!=='application/json')throw Error('INVALID_BODY');
  try{const v=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await readBody(request)));if(!v||typeof v!=='object'||Array.isArray(v))throw 0;return v;}
  catch(e){if(e?.message==='BODY_TOO_LARGE')throw e;throw Error('INVALID_BODY');}
}
function exact(obj,keys,required=[]){
  if(!obj||typeof obj!=='object'||Array.isArray(obj)||Object.keys(obj).some(k=>!keys.includes(k))||required.some(k=>!Object.hasOwn(obj,k)))throw Error('INVALID_ARGUMENTS');
}
/** Stable, non-sensitive error codes only (never raw exception text with paths or data). */
export function publicError(e){
  const m=String(e?.message||'');
  if(/^ACTIVE_JOB_CONFLICT:[0-9a-f-]{36}$/.test(m))return m;
  if(/^MAIL_SCOPE_DENIED/.test(m))return 'MAIL_SCOPE_DENIED';
  if(['ACCESS_DENIED','JOB_NOT_FOUND','GRANT_NOT_FOUND'].includes(m))return 'NOT_FOUND';
  if(/^[A-Z][A-Z0-9_]{2,60}$/.test(m))return m;
  return 'INVALID_REQUEST';
}

export function hashApprovalPassword(password,saltHex=randomBytes(16).toString('hex')){
  if(typeof password!=='string'||password.length<16||password.length>256)throw Error('WEAK_APPROVAL_PASSWORD');
  return {salt:saltHex,hash:scryptSync(password,Buffer.from(saltHex,'hex'),32).toString('hex')};
}

function tools(kinds){
  const kindNames=kinds.names();
  return [
    {name:'rian_v2_devices',description:'List this tenant\'s registered PCs and whether each V2 agent is online. Read only.',inputSchema:{type:'object',properties:{},additionalProperties:false}},
    {name:'rian_v2_start_job',description:'Start a long-running remote job and return job_id IMMEDIATELY (no 28 s limit). If no exact-scope standing grant exists, the result contains approval_url for the owner to approve once in a browser. Kinds: mail.sync {days 1-14, maxMessages 1-1000} merges new mail into the local index with automatic backup; mail.search {query, limit 1-20} returns metadata only; mail.read {messageId} returns ONE selected message body and always needs its own approval'+(kindNames.includes('diag.wait')?'; diag.wait {seconds 1-900} is a synthetic progress-only test job':'')+'. Never sends, deletes or moves mail. Re-sending the same request returns the same job (duplicate prevention).',
      inputSchema:{type:'object',properties:{device:{type:'string'},kind:{type:'string',enum:kindNames},params:{type:'object'},request_key:{type:'string',pattern:'^[A-Za-z0-9_-]{16,80}$'}},required:['device','kind','params'],additionalProperties:false}},
    {name:'rian_v2_job_status',description:'Get state, progress and (when finished) the result of a job. wait_seconds (0-20) waits for a change. Never retry a job whose state is RUNNING or UNKNOWN_DO_NOT_RETRY.',
      inputSchema:{type:'object',properties:{job_id:{type:'string'},wait_seconds:{type:'integer',minimum:0,maximum:20}},required:['job_id'],additionalProperties:false}},
    {name:'rian_v2_list_jobs',description:'List recent jobs of this tenant (no results).',inputSchema:{type:'object',properties:{limit:{type:'integer',minimum:1,maximum:50}},additionalProperties:false}},
    {name:'rian_v2_cancel_job',description:'Cancel a pending approval, a queued job, or request a running job to stop safely.',inputSchema:{type:'object',properties:{job_id:{type:'string'}},required:['job_id'],additionalProperties:false}},
    {name:'rian_v2_list_grants',description:'List active exact-scope standing grants (owner pre-approvals) and their remaining runs.',inputSchema:{type:'object',properties:{},additionalProperties:false}},
    {name:'rian_v2_revoke_grant',description:'Revoke a standing grant immediately.',inputSchema:{type:'object',properties:{grant_id:{type:'string'}},required:['grant_id'],additionalProperties:false}}
  ];
}
const text=v=>({content:[{type:'text',text:JSON.stringify(v)}]});

export function createLongJobHandler({directory,queue,approvers,publicOrigin,formSecret,clock=()=>Date.now()}){
  if(!(directory instanceof TenantDirectory)||!(queue instanceof LongJobQueue))throw Error('INVALID_LONG_JOB_HANDLER');
  if(typeof publicOrigin!=='string'||!/^https?:\/\/[^/?#]+$/.test(publicOrigin))throw Error('INVALID_PUBLIC_ORIGIN');
  if(!/^https:\/\//.test(publicOrigin)&&!/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(publicOrigin))throw Error('HTTPS_ORIGIN_REQUIRED');
  if(typeof formSecret!=='string'||Buffer.byteLength(formSecret)<48)throw Error('INVALID_FORM_SECRET');
  const approverMap=new Map();
  for(const a of approvers||[]){
    if(!a||typeof a.tenantId!=='string'||typeof a.ownerId!=='string'||!/^[a-f0-9]{32}$/.test(a.salt||'')||!/^[a-f0-9]{64}$/.test(a.hash||''))throw Error('INVALID_APPROVER');
    approverMap.set(a.tenantId+'|'+a.ownerId,a);
  }
  const failures=new Map();
  const nowS=()=>Math.floor(clock()/1000);
  const formTicket=(jobId,exp)=>{const nonce=randomBytes(12).toString('hex'),v=jobId+'.'+exp+'.'+nonce;return v+'.'+createHmac('sha256',formSecret).update('rian-v2-approve|'+v).digest('hex');};
  const ticketOK=(t,jobId)=>{
    if(typeof t!=='string'||t.length>300)return false;
    const p=t.split('.');if(p.length!==4||p[0]!==jobId||!/^\d+$/.test(p[1])||!/^[a-f0-9]{24}$/.test(p[2])||!/^[a-f0-9]{64}$/.test(p[3]))return false;
    const want=createHmac('sha256',formSecret).update('rian-v2-approve|'+p.slice(0,3).join('.')).digest();
    return timingSafeEqual(want,Buffer.from(p[3],'hex'))&&Number(p[1])>nowS();
  };
  const passwordOK=(approver,password)=>{
    if(!approver||typeof password!=='string'||password.length<16||password.length>256)return false;
    return timingSafeEqual(scryptSync(password,Buffer.from(approver.salt,'hex'),32),Buffer.from(approver.hash,'hex'));
  };
  const page=(body,status=200)=>new Response('<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RIAN Commander V2 승인</title><style>body{background:#0b1423;color:#e3ebfa;font:16px system-ui;margin:0}main{max-width:560px;margin:6vh auto;padding:28px;background:#172840;border:1px solid #334965;border-radius:16px}li,p{color:#c4d0e3;line-height:1.7}input,button{box-sizing:border-box;width:100%;padding:12px;border-radius:8px;font:inherit}button{background:#367afa;color:#fff;border:0;margin-top:16px;font-weight:600}fieldset{border:1px solid #334965;border-radius:10px;margin-top:14px}code{overflow-wrap:anywhere}</style><main>'+body+'</main></html>',
    // 'same-origin', not 'no-referrer': with no-referrer browsers send "Origin: null" on the
    // approval form POST (Fetch spec), so the Origin check below rejected every real browser.
    {status,headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','referrer-policy':'same-origin','x-content-type-options':'nosniff','content-security-policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"}});
  const approvalUrl=id=>publicOrigin+'/v2/approve/'+id;
  const withApproval=s=>s.state==='AWAITING_APPROVAL'?{...s,approval_url:approvalUrl(s.job_id)}:s;

  async function callTool(actor,name,args,clientRef){
    if(!args||typeof args!=='object'||Array.isArray(args))throw Error('INVALID_ARGUMENTS');
    if(name==='rian_v2_devices'){exact(args,[]);return {devices:queue.devices(actor)};}
    if(name==='rian_v2_start_job'){
      exact(args,['device','kind','params','request_key'],['device','kind','params']);
      if(typeof args.device!=='string')throw Error('INVALID_ARGUMENTS');
      return withApproval(queue.request({actor,deviceId:args.device,kind:args.kind,params:args.params,requestKey:args.request_key,clientRef}));
    }
    if(name==='rian_v2_job_status'){
      exact(args,['job_id','wait_seconds'],['job_id']);
      const wait=args.wait_seconds===undefined?0:args.wait_seconds;
      if(!Number.isInteger(wait)||wait<0||wait>20)throw Error('INVALID_ARGUMENTS');
      let s=queue.get({actor,jobId:args.job_id});
      const first=JSON.stringify([s.state,s.progress]),until=Date.now()+wait*1000;
      while(!s.terminal&&Date.now()<until){await sleep(Math.min(1000,until-Date.now()));s=queue.get({actor,jobId:args.job_id});if(JSON.stringify([s.state,s.progress])!==first)break;}
      return withApproval(s);
    }
    if(name==='rian_v2_list_jobs'){exact(args,['limit']);return {jobs:queue.list({actor,limit:args.limit===undefined?10:args.limit}).map(withApproval)};}
    if(name==='rian_v2_cancel_job'){exact(args,['job_id'],['job_id']);return queue.cancel({actor,jobId:args.job_id});}
    if(name==='rian_v2_list_grants'){exact(args,[]);return {grants:queue.listGrants(actor)};}
    if(name==='rian_v2_revoke_grant'){exact(args,['grant_id'],['grant_id']);return queue.revokeGrant({actor,grantId:args.grant_id});}
    throw Error('UNKNOWN_TOOL');
  }

  const authenticate=(request,kind)=>{
    let actor;try{actor=directory.authenticate(request.headers.get('authorization'));}catch{throw Error('UNAUTHENTICATED');}
    if(actor.kind!==kind)throw Error('UNAUTHENTICATED');
    return actor;
  };
  async function mcp(request){
    const actor=authenticate(request,'owner');
    const clientRef=request.headers.get('x-rian-client-ref');
    const x=await jsonBody(request),id=x.id??null;
    if(x.method==='notifications/initialized')return new Response(null,{status:202});
    let result;
    if(x.method==='initialize')result={protocolVersion:'2025-03-26',capabilities:{tools:{}},serverInfo:{name:'rian-commander-v2-jobs',version:'2.0.0'}};
    else if(x.method==='tools/list')result={tools:tools(queue.kinds)};
    else if(x.method==='ping')result={};
    else if(x.method==='tools/call'){
      try{result=text(await callTool(actor,x.params?.name,x.params?.arguments??{},clientRef&&/^[a-f0-9]{16,64}$/.test(clientRef)?clientRef:null));}
      catch(e){result={isError:true,content:[{type:'text',text:publicError(e)}]};}
    }else return json({jsonrpc:'2.0',id,error:{code:-32601,message:'Unknown method'}});
    return json({jsonrpc:'2.0',id,result});
  }

  function approvalPage(preview,msg=''){
    const exp=nowS()+600,ticket=formTicket(preview.jobId,exp);
    const when=t=>new Date(t*1000).toLocaleString('ko-KR',{timeZone:'Asia/Seoul'});
    return page('<h1>RIAN Commander V2 작업 승인</h1>'+
      '<p>대상 PC: <strong>'+escapeHtml(preview.device)+'</strong><br>작업: <strong>'+escapeHtml(preview.label)+'</strong></p>'+
      '<ul>'+preview.lines.map(l=>'<li>'+escapeHtml(l)+'</li>').join('')+'</ul>'+
      '<p>정확한 매개변수: <code>'+escapeHtml(JSON.stringify(preview.params))+'</code><br>최대 실행 시간: '+Math.round(preview.maxRuntimeSeconds/60)+'분 · 승인 요청 만료: '+escapeHtml(when(preview.approvalExpiresAt))+' (한국시간)</p>'+
      '<p>임의 명령, PowerShell, 다른 PC, 메일 발송·삭제는 포함되지 않습니다. 승인 전에는 아무것도 실행되지 않습니다.</p>'+
      (msg?'<p role="alert"><strong>'+escapeHtml(msg)+'</strong></p>':'')+
      '<form method="POST" action="/v2/approve/'+escapeHtml(preview.jobId)+'"><input type="hidden" name="ticket" value="'+escapeHtml(ticket)+'">'+
      (preview.grantable?'<fieldset><legend>반복 승인 (선택)</legend><label><input type="checkbox" name="standing" value="1" style="width:auto"> 같은 PC·같은 작업·같은 매개변수에 한해 아래 기간·횟수 동안 암호 없이 다시 실행 허용</label>'+
        '<label for="minutes">기간(분, 1~1440)</label><input id="minutes" name="minutes" type="number" min="1" max="1440" value="1440">'+
        '<label for="runs">추가 실행 횟수 (1~50)</label><input id="runs" name="runs" type="number" min="1" max="50" value="10"></fieldset>'
        :'<p>이 작업은 반복 승인 대상이 아니며 이번 1건만 승인됩니다.</p>')+
      '<label for="password">소유자 승인 암호</label><input id="password" name="password" type="password" minlength="16" autocomplete="current-password" required>'+
      '<button type="submit">이 범위로 승인</button></form>');
  }

  async function approve(request,jobId){
    const origin=request.headers.get('origin');
    // A browser that still sends "Origin: null" is accepted only with its own same-origin fetch
    // metadata (Sec-Fetch-Site cannot be set by page scripts). The HMAC ticket and password still apply.
    const sameOriginBrowser=origin==='null'&&request.headers.get('sec-fetch-site')==='same-origin';
    if(origin!==publicOrigin&&!sameOriginBrowser)return page('<h1>다른 출처의 승인 요청 차단</h1>',403);
    if(request.headers.get('content-type')?.split(';')[0].trim().toLowerCase()!=='application/x-www-form-urlencoded')return page('<h1>잘못된 승인 양식</h1>',400);
    let form;try{form=new URLSearchParams(new TextDecoder('utf-8',{fatal:true}).decode(await readBody(request,8000)));}catch{return page('<h1>잘못된 승인 양식</h1>',400);}
    let preview;try{preview=queue.approvalPreview(jobId);}catch{return page('<h1>작업을 찾을 수 없습니다.</h1>',404);}
    if(preview.state!=='AWAITING_APPROVAL')return page('<h1>이미 처리되었거나 만료된 승인 요청입니다.</h1><p>현재 상태: '+escapeHtml(preview.state)+'</p>',409);
    if(!ticketOK(form.get('ticket'),jobId))return approvalPage(preview,'승인 양식이 만료되었습니다. 다시 입력하세요.');
    const ip=(request.headers.get('x-forwarded-for')||'local').split(',')[0].trim().slice(0,60),key=preview.tenantId+'|'+ip;
    // Per client and per job: a spoofed X-Forwarded-For cannot buy unlimited guesses for one job.
    const jobKey='job|'+jobId;
    let f=failures.get(key);if(!f||f.until<nowS())f={count:0,until:nowS()+600};
    let g=failures.get(jobKey);if(!g||g.until<nowS())g={count:0,until:nowS()+900};
    if(f.count>=5||g.count>=10)return page('<h1>암호 시도 횟수 초과</h1><p>잠시 뒤 다시 시도하세요.</p>',429);
    const approver=approverMap.get(preview.tenantId+'|'+preview.ownerId);
    if(!passwordOK(approver,form.get('password')||'')){f.count++;g.count++;failures.set(key,f);failures.set(jobKey,g);return approvalPage(preview,'승인 암호가 일치하지 않습니다.');}
    failures.delete(key);
    let grant=null;
    if(form.get('standing')==='1'){
      const minutes=Number(form.get('minutes')),maxRuns=Number(form.get('runs'));
      grant={minutes,maxRuns};
    }
    try{
      const r=queue.approve({approver:{tenantId:preview.tenantId,ownerId:preview.ownerId},jobId,grant});
      return page('<h1>승인 완료</h1><p>작업이 대기열에 들어갔습니다. PC 에이전트가 가져가 실행하며, ChatGPT에서 rian_v2_job_status로 진행률과 결과를 확인할 수 있습니다.</p>'+
        (r.grantId?'<p>반복 승인 '+escapeHtml(String(grant.maxRuns))+'회 / '+escapeHtml(String(grant.minutes))+'분이 같은 범위에 한해 적용됩니다. ChatGPT의 rian_v2_revoke_grant로 즉시 취소할 수 있습니다.</p>':''));
    }catch(e){return page('<h1>승인하지 못했습니다</h1><p>'+escapeHtml(publicError(e))+'</p>',409);}
  }

  async function agent(request,path){
    const actor=authenticate(request,'agent');
    const body=await jsonBody(request);
    if(path==='/v2/agent/claim'){exact(body,['deviceId'],['deviceId']);return json(queue.claim({actor,deviceId:body.deviceId}));}
    const m=/^\/v2\/agent\/jobs\/([0-9a-f-]{36})\/(heartbeat|complete)$/.exec(path);
    if(!m)return json({error:'NOT_FOUND'},404);
    if(m[2]==='heartbeat'){exact(body,['leaseToken','progress'],['leaseToken']);return json(queue.heartbeat({actor,jobId:m[1],leaseToken:body.leaseToken,progress:body.progress??{}}));}
    exact(body,['leaseToken','outcome','exitCode','output'],['leaseToken','outcome','exitCode','output']);
    return json(queue.complete({actor,jobId:m[1],...body}));
  }

  return async function handle(request){
    const url=new URL(request.url),path=url.pathname,method=request.method.toUpperCase();
    try{
      if(url.search||url.hash)return json({error:'NOT_FOUND'},404);
      const approveMatch=/^\/v2\/approve\/([0-9a-f-]{36})$/.exec(path);
      if(approveMatch&&UUID.test(approveMatch[1])){
        if(method==='GET'){
          let preview;try{preview=queue.approvalPreview(approveMatch[1]);}catch{return page('<h1>작업을 찾을 수 없습니다.</h1>',404);}
          if(preview.state!=='AWAITING_APPROVAL')return page('<h1>이미 처리되었거나 만료된 승인 요청입니다.</h1><p>현재 상태: '+escapeHtml(preview.state)+'</p>',409);
          return approvalPage(preview);
        }
        if(method==='POST')return await approve(request,approveMatch[1]);
      }
      if(method==='POST'&&path==='/v2/mcp')return await mcp(request);
      if(method==='POST'&&path.startsWith('/v2/agent/'))return await agent(request,path);
      return json({error:'NOT_FOUND'},404);
    }catch(e){
      const code=publicError(e);
      if(code==='UNAUTHENTICATED')return json({error:code},401);
      if(code==='NOT_FOUND')return json({error:'NOT_FOUND'},404);
      if(code==='BODY_TOO_LARGE')return json({error:code},413);
      if(/LEASE|CONFLICT|NOT_RUNNING|ALREADY|LATE/.test(code))return json({error:code},409);
      return json({error:code},400);
    }
  };
}
export const _test={publicError};
export const clientRefFor=clientId=>createHash('sha256').update('rian-v2-client|'+clientId).digest('hex').slice(0,32);
