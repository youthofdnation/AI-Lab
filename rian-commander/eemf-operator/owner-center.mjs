/** Fixed owner permission center, isolated to the V2 staging service. */
import {createHash,createHmac,randomBytes,scryptSync,timingSafeEqual} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {generateRegistrationOptions,verifyRegistrationResponse,generateAuthenticationOptions,verifyAuthenticationResponse} from '@simplewebauthn/server';
import {OwnerCenterStore} from './owner-center-store.mjs';
import {planReadPolicy} from './read-policy-scope.mjs';

const CLIENT=readFileSync(new URL('./owner-center-client.js',import.meta.url));
const BROWSER=readFileSync(new URL('./node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js',import.meta.url));
const JSON_HEADERS={'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'};
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const escapeHtml=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const sha=s=>createHash('sha256').update(s).digest('hex');
const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{...JSON_HEADERS,...headers}});
const fail=(code,status=400)=>json({error:code},status);
const sessionCookie=(token,maxAge)=>`__Host-rian_owner=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
const flowCookie=(token,maxAge)=>`__Host-rian_flow=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
function cookie(request,name){
  const header=request.headers.get('cookie')||'';
  if(header.length>4096)return null;
  return header.split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='))?.slice(name.length+1)||null;
}
async function body(request){
  if(request.headers.get('content-type')?.split(';')[0].trim().toLowerCase()!=='application/json')throw Error('INVALID_BODY');
  const text=await request.text();
  if(text.length>80000)throw Error('BODY_TOO_LARGE');
  const value=JSON.parse(text);
  if(!value||typeof value!=='object'||Array.isArray(value))throw Error('INVALID_BODY');
  return value;
}
function exact(v,keys,required=[]){
  if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).some(k=>!keys.includes(k))||required.some(k=>!Object.hasOwn(v,k)))
    throw Error('INVALID_BODY');
}
function html(content,status=200){
  return new Response('<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'+
    '<title>RIAN Commander 권한 관리</title><style>body{margin:0;background:#0b1423;color:#edf3ff;font:16px system-ui}main{max-width:1000px;margin:3vh auto;padding:24px}section,article{background:#172840;border:1px solid #344b67;border-radius:12px;padding:18px;margin:14px 0}h1,h2,h3{margin-top:0}p,li,small{color:#c4d0e3;line-height:1.5}button,input,select{font:inherit;padding:9px;border-radius:7px}button{background:#367afa;color:white;border:0;cursor:pointer;margin:4px}button:disabled{opacity:.6}input[type=password],input[type=text]{width:min(100%,430px);box-sizing:border-box}label{display:block;margin:8px 0}label.inline{display:inline-block;margin-right:12px}code{overflow-wrap:anywhere}#notice{min-height:1.5em}[role=alert]{color:#ffbd83}[role=status]{color:#8fe6b0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}.muted{color:#9ab0cb}</style>'+content+
    '<script src="/v2/permissions/vendor.js" defer></script><script src="/v2/permissions/app.js" defer></script></html>',
    {status,headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',
      'referrer-policy':'no-referrer','content-security-policy':"default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"}});
}

export function createOwnerCenter({store,queue,directory,approvers,publicOrigin,formSecret,clock=()=>Date.now()}){
  const rpID=new URL(publicOrigin).hostname;
  if(!/^https:\/\//.test(publicOrigin)&&!/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(publicOrigin))throw Error('HTTPS_ORIGIN_REQUIRED');
  if(typeof formSecret!=='string'||Buffer.byteLength(formSecret)<48)throw Error('INVALID_FORM_SECRET');
  if(!Array.isArray(approvers)||approvers.length<1||approvers.length>32)throw Error('INVALID_APPROVERS');
  const auth=new OwnerCenterStore({store,clock,rpID});
  const now=()=>Math.floor(clock()/1000);
  const sameOrigin=request=>request.headers.get('origin')===publicOrigin||
    (request.headers.get('origin')==='null'&&request.headers.get('sec-fetch-site')==='same-origin');
  const rateKey=request=>createHmac('sha256',formSecret).update('center-login|'+
    (request.headers.get('x-forwarded-for')||'unknown').split(',')[0].trim().slice(0,80)).digest('hex');
  const session=request=>auth.session(cookie(request,'__Host-rian_owner'));
  const actor=s=>directory.ownerFromVerifiedSession(s.tenant,s.owner);
  const passkeys=s=>auth.credentials(s.tenant,s.owner);
  const summary=s=>{
    const a=actor(s),requests=queue.listReadPolicyRequests(a,50);
    const pendingJobs=store.db.prepare("SELECT id FROM long_jobs WHERE tenant=? AND owner=? AND state IN ('AWAITING_APPROVAL','APPROVAL_EXPIRED') ORDER BY created DESC LIMIT 50")
      .all(s.tenant,s.owner).map(x=>queue.approvalPreview(x.id)).filter(p=>p.state==='AWAITING_APPROVAL'||p.renewable);
    const audit=store.db.prepare('SELECT object_id,action,ts FROM audit WHERE tenant=? AND actor=? ORDER BY id DESC LIMIT 80')
      .all(s.tenant,s.owner);
    return {owner:s.owner,tenant:s.tenant,session_expires_at:s.expires_at,auth_method:s.method,
      passkeys:passkeys(s).map(k=>({id:k.id,id_suffix:k.id.slice(-8),created_at:k.created})),
      requests:requests.map(p=>({request_id:p.request_id,device:p.device,account:p.account,account_type:p.account_type,
        client_ref_suffix:p.client_ref.slice(-8),
        features:p.features,duration:p.duration,max_days:p.max_days,max_messages:p.max_messages,state:p.state,
        renewable:p.renewable,renewable_until_at:p.renewable_until_at,replace_policy_id:p.replace_policy_id,grant:p.grant})),
      grants:queue.listGrants(a),pending_jobs:pendingJobs.map(p=>({job_id:p.jobId,device:p.device,kind:p.kind,
        label:p.label,lines:p.lines,params:p.params,state:p.state,renewable:p.renewable})),
      jobs:queue.list({actor:a,limit:30}).map(j=>({job_id:j.job_id,device:j.device,kind:j.kind,state:j.state,
        created_at:j.created_at,finished_at:j.finished_at,outcome:j.outcome})),audit};
  };
  const scopeFor=(p,input)=>{
    exact(input,['features','duration','maxSyncDays','maxSyncMessages'],['features','duration','maxSyncDays','maxSyncMessages']);
    const plan=planReadPolicy({account:p.account,accountType:p.account_type,...input});
    if(plan.features.some(x=>!p.features.includes(x))||plan.maxSyncDays>p.max_days||plan.maxSyncMessages>p.max_messages)
      throw Error('POLICY_SCOPE_EXPANDED');
    return {features:plan.features,duration:plan.duration,maxSyncDays:plan.maxSyncDays,maxSyncMessages:plan.maxSyncMessages};
  };
  const policyDigest=(p,scope)=>sha(JSON.stringify({id:p.request_id,tenant:p.tenant,owner:p.owner,
    device:p.device,client_ref:p.client_ref,account:p.account,account_type:p.account_type,
    requested:p.features,duration:p.duration,max_days:p.max_days,max_messages:p.max_messages,
    replace_policy_id:p.replace_policy_id,scope}));
  const jobDigest=p=>sha(JSON.stringify({id:p.jobId,tenant:p.tenantId,owner:p.ownerId,device:p.device,
    kind:p.kind,params:p.params,state:p.state,renewable:p.renewable}));
  const authenticationOptions=async credentials=>generateAuthenticationOptions({rpID,userVerification:'required',
    allowCredentials:credentials.map(k=>({id:k.id,transports:k.transports}))});
  const verifyAssertion=async(response,challenge,tenant=null,owner=null)=>{
    const credential=auth.credential(response?.id);
    if(!credential||(tenant!==null&&(credential.tenant!==tenant||credential.owner!==owner)))throw Error('PASSKEY_NOT_REGISTERED');
    const verified=await verifyAuthenticationResponse({response,expectedChallenge:challenge,expectedOrigin:publicOrigin,
      expectedRPID:rpID,requireUserVerification:true,credential:{id:credential.id,publicKey:credential.publicKey,
        counter:credential.counter,transports:credential.transports}});
    if(!verified.verified)throw Error('PASSKEY_VERIFICATION_FAILED');
    auth.advanceCounter(credential,verified.authenticationInfo.newCounter);
    return credential;
  };

  async function api(request,path,s){
    const x=await body(request);
    if(path==='/v2/permissions/api/login/options'){
      exact(x,[]);
      const flow=randomBytes(32).toString('base64url'),options=await authenticationOptions([]);
      const challenge=auth.createChallenge({kind:'login',challenge:options.challenge,flowSha:sha(flow)});
      return json({challenge_id:challenge.id,optionsJSON:options},200,{'set-cookie':flowCookie(flow,300)});
    }
    if(path==='/v2/permissions/api/login/verify'){
      exact(x,['challenge_id','response'],['challenge_id','response']);
      const flow=cookie(request,'__Host-rian_flow');
      if(!flow)return fail('CHALLENGE_NOT_FOUND',403);
      const c=auth.consumeChallenge({id:x.challenge_id,kind:'login',flowSha:sha(flow)});
      const credential=await verifyAssertion(x.response,c.challenge);
      const created=auth.createSession({tenant:credential.tenant,owner:credential.owner,method:'passkey'});
      return json({ok:true},200,{'set-cookie':sessionCookie(created.token,1800)});
    }
    if(!s)return fail('OWNER_LOGIN_REQUIRED',401);
    if(path==='/v2/permissions/api/logout'){
      exact(x,[]);auth.logout(s);return json({ok:true},200,{'set-cookie':sessionCookie('',0)});
    }
    if(path==='/v2/permissions/api/register/options'){
      exact(x,[]);
      if(s.method!=='password')return fail('PASSWORD_RECOVERY_LOGIN_REQUIRED',403);
      const existing=passkeys(s),userID=createHmac('sha256',formSecret).update('passkey-user|'+s.tenant+'|'+s.owner).digest();
      const options=await generateRegistrationOptions({rpName:'RIAN Commander V2',rpID,userName:s.owner,
        userID,attestationType:'none',supportedAlgorithmIDs:[-7,-257],
        excludeCredentials:existing.map(k=>({id:k.id,transports:k.transports})),
        authenticatorSelection:{residentKey:'required',userVerification:'required'}});
      const c=auth.createChallenge({kind:'register',challenge:options.challenge,tenant:s.tenant,owner:s.owner,sessionSha:s.sha});
      return json({challenge_id:c.id,optionsJSON:options});
    }
    if(path==='/v2/permissions/api/register/verify'){
      exact(x,['challenge_id','response'],['challenge_id','response']);
      if(s.method!=='password')return fail('PASSWORD_RECOVERY_LOGIN_REQUIRED',403);
      const c=auth.consumeChallenge({id:x.challenge_id,kind:'register',tenant:s.tenant,owner:s.owner,sessionSha:s.sha});
      const verified=await verifyRegistrationResponse({response:x.response,expectedChallenge:c.challenge,
        expectedOrigin:publicOrigin,expectedRPID:rpID,requireUserVerification:true});
      if(!verified.verified||!verified.registrationInfo?.credential)throw Error('PASSKEY_REGISTRATION_FAILED');
      auth.saveCredential({tenant:s.tenant,owner:s.owner,credential:verified.registrationInfo.credential,
        transports:x.response?.response?.transports||verified.registrationInfo.credential.transports||[]});
      return json({registered:true});
    }
    if(path==='/v2/permissions/api/passkey/revoke'){
      exact(x,['id'],['id']);
      if(s.method!=='password')return fail('PASSWORD_RECOVERY_LOGIN_REQUIRED',403);
      return json(auth.revokeCredential({tenant:s.tenant,owner:s.owner,id:x.id}));
    }
    if(path==='/v2/permissions/api/change'){
      exact(x,['grant_id','scope'],['grant_id','scope']);
      const p=queue.prepareReadPolicyChange({actor:actor(s),grantId:x.grant_id,scope:x.scope});
      return json({request_id:p.request_id,state:p.state});
    }
    if(path==='/v2/permissions/api/revoke'){
      exact(x,['grant_id'],['grant_id']);
      return json(queue.revokeGrant({actor:actor(s),grantId:x.grant_id}));
    }
    if(path==='/v2/permissions/api/approve/options'){
      exact(x,['request_id','job_id','scope']);
      if(!!x.request_id===!!x.job_id)throw Error('INVALID_APPROVAL_TARGET');
      const keys=passkeys(s);
      if(!keys.length)throw Error('PASSKEY_NOT_REGISTERED');
      let kind,requestId,scopeHash,scopeJson=null;
      if(x.request_id){
        const p=queue.readPolicyPreview(x.request_id);
        if(p.tenant!==s.tenant||p.owner!==s.owner||!(p.state==='PENDING'||p.renewable))throw Error('APPROVAL_NOT_PENDING');
        const chosen=scopeFor(p,x.scope);
        kind='approve_policy';requestId=p.request_id;scopeHash=policyDigest(p,chosen);scopeJson=JSON.stringify(chosen);
      }else{
        const p=queue.approvalPreview(x.job_id);
        if(p.tenantId!==s.tenant||p.ownerId!==s.owner||!(p.state==='AWAITING_APPROVAL'||p.renewable))
          throw Error('APPROVAL_NOT_PENDING');
        kind='approve_job';requestId=p.jobId;scopeHash=jobDigest(p);
      }
      const options=await authenticationOptions(keys);
      const c=auth.createChallenge({kind,challenge:options.challenge,tenant:s.tenant,owner:s.owner,
        sessionSha:s.sha,requestId,scopeHash,scopeJson});
      return json({challenge_id:c.id,optionsJSON:options});
    }
    if(path==='/v2/permissions/api/approve/verify'){
      exact(x,['challenge_id','response','kind'],['challenge_id','response','kind']);
      if(!['approve_policy','approve_job'].includes(x.kind))throw Error('INVALID_APPROVAL_TARGET');
      const c=auth.consumeChallenge({id:x.challenge_id,kind:x.kind,tenant:s.tenant,owner:s.owner,sessionSha:s.sha});
      await verifyAssertion(x.response,c.challenge,s.tenant,s.owner);
      if(c.kind==='approve_policy'){
        const p=queue.readPolicyPreview(c.request_id),chosen=JSON.parse(c.scope_json);
        if(p.tenant!==s.tenant||p.owner!==s.owner||policyDigest(p,chosen)!==c.scope_hash)
          throw Error('POLICY_SCOPE_CHANGED');
        const result=queue.approveReadPolicy({id:p.request_id,tenant:s.tenant,owner:s.owner,scopeOverride:chosen});
        store.audit(s.tenant,s.owner,p.request_id,'READ_POLICY_APPROVED_WITH_PASSKEY',now());
        return json(result);
      }
      const p=queue.approvalPreview(c.request_id);
      if(p.tenantId!==s.tenant||p.ownerId!==s.owner||jobDigest(p)!==c.scope_hash)throw Error('JOB_SCOPE_CHANGED');
      const result=queue.approve({approver:{tenantId:s.tenant,ownerId:s.owner},jobId:c.request_id});
      store.audit(s.tenant,s.owner,c.request_id,'LONG_JOB_APPROVED_WITH_PASSKEY',now());
      return json(result);
    }
    return fail('NOT_FOUND',404);
  }

  return async function handle(request){
    const url=new URL(request.url),path=url.pathname,method=request.method.toUpperCase();
    if(url.search||url.hash)return fail('NOT_FOUND',404);
    if(method==='GET'&&path==='/v2/permissions/vendor.js')return new Response(BROWSER,{headers:{'content-type':'text/javascript; charset=utf-8','cache-control':'public, max-age=86400','x-content-type-options':'nosniff'}});
    if(method==='GET'&&path==='/v2/permissions/app.js')return new Response(CLIENT,{headers:{'content-type':'text/javascript; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'}});
    const s=session(request);
    if(method==='GET'&&path==='/v2/permissions'){
      return html(s?'<main><h1>RIAN Commander 권한 관리센터</h1><p class="muted">승인 대기 요청을 자동 확인합니다. 새 링크가 필요하지 않습니다.</p><div id="notice" role="status"></div><div id="center"></div></main>':
        '<main><h1>RIAN Commander 권한 관리센터</h1><section><p>최초 소유자 인증 후 패스키를 등록할 수 있습니다. 이후 Windows Hello, Touch ID 또는 호환 모바일 인증으로 로그인하고 승인합니다.</p>'+
        '<form method="POST" action="/v2/permissions/login"><label for="password">소유자 복구 암호</label><input id="password" name="password" type="password" minlength="16" autocomplete="current-password" required><button type="submit">최초 인증 또는 복구 로그인</button></form><p>등록된 패스키가 있다면 아래 버튼을 사용하세요.</p><button id="passkey-login" type="button">패스키로 로그인</button><p id="notice" role="status"></p></section></main>');
    }
    if(method==='GET'&&path==='/v2/permissions/api/state'){
      if(!s)return fail('OWNER_LOGIN_REQUIRED',401);
      try{return json(summary(s));}catch{return fail('STATE_UNAVAILABLE',500);}
    }
    if(method==='POST'&&path==='/v2/permissions/login'){
      if(!sameOrigin(request))return html('<main><h1>다른 출처의 로그인 요청 차단</h1></main>',403);
      if(request.headers.get('content-type')?.split(';')[0].trim().toLowerCase()!=='application/x-www-form-urlencoded')return fail('INVALID_BODY');
      const form=new URLSearchParams(await request.text()),password=form.get('password')||'',key=rateKey(request);
      if(!auth.loginAllowed(key))return html('<main><h1>로그인 시도 횟수 초과</h1><p>잠시 뒤 같은 주소에서 다시 시도하세요.</p></main>',429);
      let matches=[];
      if(password.length>=16&&password.length<=256){
        for(const a of approvers){
          const hash=scryptSync(password,Buffer.from(a.salt,'hex'),32),known=Buffer.from(a.hash,'hex');
          if(timingSafeEqual(hash,known))matches.push(a);
        }
      }
      if(matches.length!==1){auth.failedLogin(key);return html('<main><h1>소유자 인증 실패</h1><p role="alert">암호가 일치하지 않습니다. 권한은 변경되지 않았습니다.</p><a href="/v2/permissions">관리센터로 돌아가기</a></main>',401);}
      auth.clearLoginFailure(key);
      const created=auth.createSession({tenant:matches[0].tenantId,owner:matches[0].ownerId,method:'password'});
      return new Response(null,{status:303,headers:{location:'/v2/permissions','cache-control':'no-store','set-cookie':sessionCookie(created.token,1800)}});
    }
    if(method==='POST'&&path.startsWith('/v2/permissions/api/')){
      if(!sameOrigin(request))return fail('CROSS_ORIGIN_BLOCKED',403);
      try{return await api(request,path,s);}catch(e){
        const code=String(e?.message||'INVALID_REQUEST');
        const publicCode=/^[A-Z][A-Z0-9_]{2,60}$/.test(code)?code:'INVALID_REQUEST';
        return fail(publicCode,['CHALLENGE_NOT_FOUND','PASSKEY_COUNTER_REPLAY','POLICY_SCOPE_CHANGED','JOB_SCOPE_CHANGED','APPROVAL_NOT_PENDING','READ_POLICY_ALREADY_ACTIVE'].includes(publicCode)?409:400);
      }
    }
    return fail('NOT_FOUND',404);
  };
}
