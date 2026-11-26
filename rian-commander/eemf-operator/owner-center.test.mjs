import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomBytes,generateKeyPairSync,sign} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {TenantDirectory} from './tenant-artifact-core.mjs';
import {StagingSqlite} from './staging-sqlite.mjs';
import {LongJobQueue} from './durable-long-jobs.mjs';
import {LongJobKinds} from './long-job-kinds.mjs';
import {hashApprovalPassword} from './long-job-http.mjs';
import {createOwnerCenter} from './owner-center.mjs';
import {OwnerCenterStore} from './owner-center-store.mjs';
import {createStagingService,stagingConfigFromEnv} from './staging-server.mjs';
import {encodeCBOR} from '@levischuck/tiny-cbor';

const origin='https://center.example.test';
const sha=x=>createHash('sha256').update(x).digest('hex');
const b64=x=>Buffer.from(x).toString('base64url');
function syntheticPasskey(){
  const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const jwk=publicKey.export({format:'jwk'}),id=randomBytes(32),rpHash=createHash('sha256').update('center.example.test').digest();
  const cose=Buffer.from(encodeCBOR(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,'base64url')],[-3,Buffer.from(jwk.y,'base64url')]])));
  const clientData=(type,challenge,clientOrigin=origin)=>Buffer.from(JSON.stringify({type,challenge,origin:clientOrigin,crossOrigin:false}));
  return {
    id:b64(id),
    registration(challenge){
      const length=Buffer.alloc(2);length.writeUInt16BE(id.length);
      const authData=Buffer.concat([rpHash,Buffer.from([0x45]),Buffer.alloc(4),Buffer.alloc(16),length,id,cose]);
      const attestation=encodeCBOR(new Map([['fmt','none'],['attStmt',new Map()],['authData',new Uint8Array(authData)]]));
      return {id:b64(id),rawId:b64(id),type:'public-key',authenticatorAttachment:'platform',
        response:{clientDataJSON:b64(clientData('webauthn.create',challenge)),attestationObject:b64(attestation),transports:['internal']},
        clientExtensionResults:{}};
    },
    assertion(challenge,counter=1,{uv=true,clientOrigin=origin}={}){
      const count=Buffer.alloc(4);count.writeUInt32BE(counter);
      const authData=Buffer.concat([rpHash,Buffer.from([uv?0x05:0x01]),count]);
      const client=clientData('webauthn.get',challenge,clientOrigin);
      const signature=sign('sha256',Buffer.concat([authData,createHash('sha256').update(client).digest()]),privateKey);
      return {id:b64(id),rawId:b64(id),type:'public-key',response:{authenticatorData:b64(authData),
        clientDataJSON:b64(client),signature:b64(signature),userHandle:null},clientExtensionResults:{}};
    }
  };
}
function fixture(t,clock=()=>Date.now()){
  const dir=mkdtempSync(join(tmpdir(),'rian-owner-center-'));
  const filename=join(dir,'stage.db'),storageKey=randomBytes(32).toString('hex');
  const tokens=['oa','ob','aa','ab'].map(()=>randomBytes(40).toString('base64url'));
  const principals=['oa','ob','aa','ab'].map((id,i)=>({id,tenantId:i%2===0?'A':'B',
    kind:i<2?'owner':'agent',...(i>=2?{deviceId:i===2?'pcA':'pcB'}:{}),tokenSha256:sha(tokens[i])}));
  const devices=[{id:'pcA',tenantId:'A'},{id:'pcB',tenantId:'B'}];
  const directory=new TenantDirectory({principals,devices});
  const store=new StagingSqlite({filename,encryptionKeyHex:storageKey});
  const queue=new LongJobQueue({directory,store,clock,kinds:new LongJobKinds({allowMailReviewTools:true}),
    deviceKinds:{pcA:['mail.status','mail.sync','mail.search','mail.recent','mail.read','mail.review_pending'],pcB:['mail.status']}});
  const pw='synthetic-center-owner-password-'+randomBytes(6).toString('hex');
  const approvers=[{tenantId:'A',ownerId:'oa',...hashApprovalPassword(pw)},
    {tenantId:'B',ownerId:'ob',...hashApprovalPassword('different-synthetic-owner-password')}];
  const secret=randomBytes(48).toString('hex');
  const center=createOwnerCenter({store,queue,directory,approvers,publicOrigin:origin,formSecret:secret,clock});
  const oa=directory.authenticate('Bearer '+tokens[0]),ob=directory.authenticate('Bearer '+tokens[1]);
  t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
  const get=async(path,cookie='')=>center(new Request(origin+path,{headers:cookie?{cookie}:{}}));
  const post=async(path,data,cookie='',extra={})=>center(new Request(origin+path,{method:'POST',
    headers:{origin,'content-type':'application/json',...(cookie?{cookie}:{}),...extra},body:JSON.stringify(data)}));
  const login=async()=>{
    const response=await center(new Request(origin+'/v2/permissions/login',{method:'POST',
      headers:{origin,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({password:pw})}));
    assert.equal(response.status,303);
    return response.headers.get('set-cookie').split(';')[0];
  };
  return {store,queue,directory,center,oa,ob,get,post,login,pw,secret,filename,storageKey,approvers,principals,devices,clock};
}

test('the fixed permission address is wired into the actual staging HTTP service',async t=>{
  const f=fixture(t);
  const service=createStagingService({store:f.store,config:{artifactsEnabled:false,jobsEnabled:true,
    allowDiagnostics:false,allowMailReviewTools:true,principals:f.principals,devices:f.devices,
    approvers:f.approvers,publicOrigin:origin,formSecret:f.secret}});
  await new Promise(resolve=>service.server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>service.server.close(resolve)));
  const port=service.server.address().port;
  const page=await fetch('http://127.0.0.1:'+port+'/v2/permissions');
  assert.equal(page.status,200);assert.match(await page.text(),/권한 관리센터/);
  const script=await fetch('http://127.0.0.1:'+port+'/v2/permissions/vendor.js');
  assert.equal(script.status,200);assert.match(script.headers.get('content-type'),/javascript/);
});

test('Google owner configuration resolves only an existing device with one owner',t=>{
  const f=fixture(t),base={RIAN_STAGE_JOBS_ENABLED:'1',RIAN_STAGE_PRINCIPALS_JSON:JSON.stringify(f.principals),
    RIAN_STAGE_DEVICES_JSON:JSON.stringify(f.devices),RIAN_STAGE_APPROVERS_JSON:JSON.stringify(f.approvers),
    RIAN_STAGE_PUBLIC_URL:origin,RIAN_STAGE_FORM_SECRET:f.secret};
  const google={deviceId:'pcA',email:'owner@example.test',clientId:'synthetic.apps.googleusercontent.com',
    clientSecret:'synthetic-client-secret-long-enough'};
  const config=stagingConfigFromEnv({...base,RIAN_STAGE_GOOGLE_OWNER_JSON:JSON.stringify(google)});
  assert.equal(config.googleOwner.tenantId,'A');assert.equal(config.googleOwner.ownerId,'oa');
  assert.throws(()=>stagingConfigFromEnv({...base,RIAN_STAGE_GOOGLE_OWNER_JSON:JSON.stringify({...google,deviceId:'unknown'})}),
    /AMBIGUOUS_GOOGLE_OWNER_CONFIGURATION/);
});

test('mobile Google identity can enroll a passkey but cannot approve work without that passkey',async t=>{
  const f=fixture(t),passkey=syntheticPasskey();
  const clientId='synthetic-client.apps.googleusercontent.com';
  const googleOwner={tenantId:'A',ownerId:'oa',email:'owner@example.test',clientId,
    clientSecret:'synthetic-client-secret-long-enough'};
  let authorization,tokenExchange,subject='synthetic-google-sub',email='owner@example.test';
  const googleClient={
    generateAuthUrl(options){authorization=options;return 'https://accounts.google.com/o/oauth2/v2/auth?state='+encodeURIComponent(options.state);},
    async getToken(options){tokenExchange=options;return {tokens:{id_token:'synthetic-id-token'}};},
    async verifyIdToken({idToken,audience}){
      assert.equal(idToken,'synthetic-id-token');assert.equal(audience,clientId);
      return {getPayload:()=>({iss:'https://accounts.google.com',audience:clientId,aud:clientId,
        nonce:authorization.nonce,email,email_verified:true,sub:subject})};
    }
  };
  const center=createOwnerCenter({store:f.store,queue:f.queue,directory:f.directory,
    approvers:f.approvers,publicOrigin:origin,formSecret:f.secret,googleOwner,googleClient});
  const start=await center(new Request(origin+'/v2/permissions/google/start'));
  assert.equal(start.status,303);
  assert.equal(new URL(start.headers.get('location')).origin,'https://accounts.google.com');
  assert.equal(authorization.code_challenge_method,'S256');
  assert.deepEqual(authorization.scope,['openid','email']);
  const callbackUrl=state=>origin+'/v2/permissions/google/callback?code=synthetic-code&state='+
    encodeURIComponent(state)+'&iss=https%3A%2F%2Faccounts.google.com';
  const state=authorization.state,flowCookie=start.headers.get('set-cookie').split(';')[0];
  assert.equal((await center(new Request(callbackUrl(state).replace('accounts.google.com','attacker.example.test'),
    {headers:{cookie:flowCookie}}))).status,401,'a wrong authorization-server issuer is denied');
  const callback=await center(new Request(callbackUrl(state),
    {headers:{cookie:flowCookie}}));
  assert.equal(callback.status,303);
  assert.equal(tokenExchange.redirect_uri,origin+'/v2/permissions/google/callback');
  assert.ok(tokenExchange.codeVerifier.length>=43);
  const sessionCookie=callback.headers.getSetCookie().find(x=>x.startsWith('__Host-rian_owner=')).split(';')[0];
  const stateResponse=await center(new Request(origin+'/v2/permissions/api/state',{headers:{cookie:sessionCookie}}));
  assert.equal((await stateResponse.json()).auth_method,'google');
  assert.equal(f.store.db.prepare("SELECT COUNT(*) AS n FROM owner_identity_bindings WHERE tenant='A'").get().n,1);
  assert.equal((await center(new Request(callbackUrl(state),
    {headers:{cookie:flowCookie}}))).status,401,'the OAuth state is single-use');
  const changed=await center(new Request(origin+'/v2/permissions/google/start'));
  subject='different-google-account';
  assert.equal((await center(new Request(callbackUrl(authorization.state),
    {headers:{cookie:changed.headers.get('set-cookie').split(';')[0]}}))).status,401,
    'a different Google subject cannot take over the same owner');
  const wrongEmail=await center(new Request(origin+'/v2/permissions/google/start'));
  subject='synthetic-google-sub';email='other@example.test';
  assert.equal((await center(new Request(callbackUrl(authorization.state),
    {headers:{cookie:wrongEmail.headers.get('set-cookie').split(';')[0]}}))).status,401,
    'a different verified email cannot log in');
  const post=(path,data)=>center(new Request(origin+path,{method:'POST',headers:{origin,
    'content-type':'application/json',cookie:sessionCookie},body:JSON.stringify(data)}));
  const pending=f.queue.prepareReadPolicy({actor:f.oa,deviceId:'pcA',clientRef:'a'.repeat(32),
    scope:{account:'owner@example.test',accountType:'outlook',features:['mail.status'],duration:'day'}});
  assert.equal((await post('/v2/permissions/api/approve/options',{request_id:pending.request_id,
    scope:{features:['mail.status'],duration:'day',maxSyncDays:14,maxSyncMessages:1000}})).status,400,
    'Google identity alone cannot approve mail access');
  const registration=await (await post('/v2/permissions/api/register/options',{})).json();
  assert.equal((await post('/v2/permissions/api/register/verify',{challenge_id:registration.challenge_id,
    response:passkey.registration(registration.optionsJSON.challenge)})).status,200);
  assert.equal(f.store.db.prepare("SELECT COUNT(*) AS n FROM passkey_credentials WHERE tenant='A'").get().n,1);
});

test('fixed center requires owner authentication and shows pending work without granting it',async t=>{
  const f=fixture(t);
  const before=await f.get('/v2/permissions');
  assert.equal(before.status,200);assert.match(await before.text(),/권한 관리센터/);
  assert.equal((await f.get('/v2/permissions/api/state')).status,401);
  const requested=f.queue.prepareReadPolicy({actor:f.oa,deviceId:'pcA',clientRef:'a'.repeat(32),
    scope:{account:'owner@example.test',accountType:'outlook',features:['mail.status','mail.sync'],duration:'day'}});
  const cookie=await f.login();
  const state=await f.get('/v2/permissions/api/state',cookie),data=await state.json();
  assert.equal(state.status,200);assert.equal(data.requests[0].request_id,requested.request_id);
  assert.equal(data.requests[0].account,'owner@example.test');
  assert.equal(data.grants.length,0,'listing a pending request must not silently approve it');
  assert.equal(data.owner,'oa');
  assert.equal((await f.post('/v2/permissions/api/approve/options',{request_id:requested.request_id,
    scope:{features:['mail.status'],duration:'day',maxSyncDays:14,maxSyncMessages:1000}},cookie)).status,400,
    'no passkey means no approval');
  assert.equal((await f.post('/v2/permissions/api/revoke',{grant_id:requested.request_id},cookie,
    {origin:'https://attacker.example.test'})).status,403);
  assert.equal((await f.get('/v2/permissions/app.js')).status,200);
  assert.equal((await f.get('/v2/permissions/vendor.js')).status,200);
});

test('registration challenge is single-use, session-bound and survives a handler restart',async t=>{
  const f=fixture(t),cookie=await f.login();
  const response=await f.post('/v2/permissions/api/register/options',{},cookie),options=await response.json();
  assert.equal(response.status,200);
  assert.equal(options.optionsJSON.rp.id,'center.example.test');
  assert.equal(options.optionsJSON.authenticatorSelection.userVerification,'required');
  const restarted=createOwnerCenter({store:f.store,queue:f.queue,directory:f.directory,approvers:f.approvers,
    publicOrigin:origin,formSecret:f.secret,clock:f.clock});
  const invalid=await restarted(new Request(origin+'/v2/permissions/api/register/verify',{method:'POST',
    headers:{origin,cookie,'content-type':'application/json'},body:JSON.stringify({challenge_id:options.challenge_id,response:{id:'fake'}})}));
  assert.equal(invalid.status,400);
  const replay=await f.post('/v2/permissions/api/register/verify',{challenge_id:options.challenge_id,response:{id:'fake'}},cookie);
  assert.equal(replay.status,409);assert.equal((await replay.json()).error,'CHALLENGE_NOT_FOUND');
  const other=await f.login();
  const next=await f.post('/v2/permissions/api/register/options',{},cookie),nextOptions=await next.json();
  assert.equal((await f.post('/v2/permissions/api/register/verify',{challenge_id:nextOptions.challenge_id,response:{id:'fake'}},other)).status,409);
});

test('a changed read policy stays pending until approval, then atomically replaces its predecessor',t=>{
  const f=fixture(t),ref='a'.repeat(32);
  const requested=f.queue.prepareReadPolicy({actor:f.oa,deviceId:'pcA',clientRef:ref,
    scope:{account:'owner@example.test',accountType:'outlook',features:['mail.status'],duration:'day'}});
  const first=f.queue.approveReadPolicy({id:requested.request_id,tenant:'A',owner:'oa'});
  const change=f.queue.prepareReadPolicyChange({actor:f.oa,grantId:first.grant_id,
    scope:{features:['mail.status','mail.search'],duration:'week',maxSyncDays:7,maxSyncMessages:500}});
  assert.equal(f.queue.listGrants(f.oa).find(g=>g.grant_id===first.grant_id)?.state,'ACTIVE');
  assert.equal(f.queue.readPolicyPreview(change.request_id).replace_policy_id,first.grant_id);
  assert.throws(()=>f.queue.approveReadPolicy({id:change.request_id,tenant:'B',owner:'ob'}),/POLICY_APPROVAL_EXPIRED/);
  assert.throws(()=>f.queue.approveReadPolicy({id:change.request_id,tenant:'A',owner:'oa',scopeOverride:{
    features:['mail.status','mail.read'],duration:'week',maxSyncDays:7,maxSyncMessages:500}}),/POLICY_SCOPE_EXPANDED/);
  const second=f.queue.approveReadPolicy({id:change.request_id,tenant:'A',owner:'oa'});
  assert.equal(second.state,'ACTIVE');
  assert.equal(f.queue.readPolicyPreview(first.grant_id).grant.state,'REVOKED');
  assert.equal(f.queue.listGrants(f.oa).filter(g=>g.kind==='read.policy').length,1);
  assert.equal(f.queue.listGrants(f.ob).length,0);
});

test('a wider MCP policy request replaces the existing grant only after owner approval',t=>{
  const f=fixture(t),ref='a'.repeat(32);
  const firstRequest=f.queue.prepareReadPolicy({actor:f.oa,deviceId:'pcA',clientRef:ref,
    scope:{account:'owner@example.test',accountType:'outlook',features:['mail.status'],duration:'day'}});
  const first=f.queue.approveReadPolicy({id:firstRequest.request_id,tenant:'A',owner:'oa'});
  const wider=f.queue.prepareReadPolicy({actor:f.oa,deviceId:'pcA',clientRef:ref,
    scope:{account:'owner@example.test',accountType:'outlook',features:['mail.status','mail.search'],duration:'week'}});
  assert.equal(wider.state,'PENDING');
  assert.equal(f.queue.readPolicyPreview(wider.request_id).replace_policy_id,first.grant_id);
  assert.equal(f.queue.listGrants(f.oa)[0].grant_id,first.grant_id);
  assert.equal(f.queue.prepareReadPolicy({actor:f.oa,deviceId:'pcA',clientRef:ref,
    scope:{account:'owner@example.test',accountType:'outlook',features:['mail.status','mail.search'],duration:'week'}}).request_id,
  wider.request_id,'repeated requests should reuse the same pending approval');
  f.queue.approveReadPolicy({id:wider.request_id,tenant:'A',owner:'oa'});
  assert.equal(f.queue.listGrants(f.oa).length,1);
  assert.equal(f.queue.listGrants(f.oa)[0].grant_id,wider.request_id);
});

test('login password failures are rate limited without creating a center session',async t=>{
  const f=fixture(t);
  for(let i=0;i<5;i++){
    const r=await f.center(new Request(origin+'/v2/permissions/login',{method:'POST',
      headers:{origin,'content-type':'application/x-www-form-urlencoded'},
      body:new URLSearchParams({password:'wrong-synthetic-password-long-enough'})}));
    assert.equal(r.status,401);
  }
  const blocked=await f.center(new Request(origin+'/v2/permissions/login',{method:'POST',
    headers:{origin,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({password:f.pw})}));
  assert.equal(blocked.status,429);
});

test('real WebAuthn verification registers, logs in and approves only the signed policy scope',async t=>{
  const f=fixture(t),passkey=syntheticPasskey(),passwordCookie=await f.login();
  const registrationOptions=await (await f.post('/v2/permissions/api/register/options',{},passwordCookie)).json();
  const registration=await f.post('/v2/permissions/api/register/verify',{
    challenge_id:registrationOptions.challenge_id,response:passkey.registration(registrationOptions.optionsJSON.challenge)},passwordCookie);
  assert.equal(registration.status,200,await registration.clone().text());
  assert.equal((await registration.json()).registered,true);
  const optionsResponse=await f.post('/v2/permissions/api/login/options',{});
  const flowCookie=optionsResponse.headers.get('set-cookie').split(';')[0],loginOptions=await optionsResponse.json();
  const loggedIn=await f.post('/v2/permissions/api/login/verify',{challenge_id:loginOptions.challenge_id,
    response:passkey.assertion(loginOptions.optionsJSON.challenge,1)},flowCookie);
  assert.equal(loggedIn.status,200,await loggedIn.clone().text());
  const passkeyCookie=loggedIn.headers.get('set-cookie').split(';')[0];
  const requested=f.queue.prepareReadPolicy({actor:f.oa,deviceId:'pcA',clientRef:'a'.repeat(32),
    scope:{account:'owner@example.test',accountType:'outlook',
      features:['mail.status','mail.sync','mail.search'],duration:'day'}});
  const scope={features:['mail.status','mail.search'],duration:'week',maxSyncDays:7,maxSyncMessages:300};
  const optionResponse=await f.post('/v2/permissions/api/approve/options',{request_id:requested.request_id,scope},passkeyCookie);
  assert.equal(optionResponse.status,200,await optionResponse.clone().text());
  const approvalOptions=await optionResponse.json();
  const noUV=await f.post('/v2/permissions/api/approve/verify',{challenge_id:approvalOptions.challenge_id,
    kind:'approve_policy',response:passkey.assertion(approvalOptions.optionsJSON.challenge,2,{uv:false})},passkeyCookie);
  assert.equal(noUV.status,400,'user presence without user verification must not grant mail access');
  assert.equal(f.queue.listGrants(f.oa).length,0);
  const replay=await f.post('/v2/permissions/api/approve/verify',{challenge_id:approvalOptions.challenge_id,
    kind:'approve_policy',response:passkey.assertion(approvalOptions.optionsJSON.challenge,2)},passkeyCookie);
  assert.equal(replay.status,409);
  const retry=await (await f.post('/v2/permissions/api/approve/options',{request_id:requested.request_id,scope},passkeyCookie)).json();
  const wrongOrigin=await f.post('/v2/permissions/api/approve/verify',{challenge_id:retry.challenge_id,
    kind:'approve_policy',response:passkey.assertion(retry.optionsJSON.challenge,2,{clientOrigin:'https://attacker.example.test'})},passkeyCookie);
  assert.equal(wrongOrigin.status,400);
  assert.equal(f.queue.listGrants(f.oa).length,0);
  const finalOptions=await (await f.post('/v2/permissions/api/approve/options',{request_id:requested.request_id,scope},passkeyCookie)).json();
  const approved=await f.post('/v2/permissions/api/approve/verify',{challenge_id:finalOptions.challenge_id,
    kind:'approve_policy',response:passkey.assertion(finalOptions.optionsJSON.challenge,2)},passkeyCookie);
  assert.equal(approved.status,200,await approved.clone().text());
  const grant=await approved.json();
  assert.equal(grant.state,'ACTIVE');assert.equal(grant.grant_id,requested.request_id);
  assert.deepEqual(grant.features,['mail.search','mail.status']);
  assert.equal(f.queue.listGrants(f.oa)[0].expires_at-f.queue.listGrants(f.oa)[0].created_at,7*86400);
  assert.equal((await f.post('/v2/permissions/api/approve/verify',{challenge_id:finalOptions.challenge_id,
    kind:'approve_policy',response:passkey.assertion(finalOptions.optionsJSON.challenge,3)},passkeyCookie)).status,409);
  const status=f.queue.request({actor:f.oa,deviceId:'pcA',kind:'mail.status',params:{},clientRef:'a'.repeat(32)});
  assert.equal(status.approval_required,false,'same OAuth connection reuses the approved policy');
  const removed=await f.post('/v2/permissions/api/passkey/revoke',{id:passkey.id},passwordCookie);
  assert.equal(removed.status,200);
  const later=await f.post('/v2/permissions/api/login/options',{}),laterFlow=later.headers.get('set-cookie').split(';')[0];
  const laterOptions=await later.json();
  const denied=await f.post('/v2/permissions/api/login/verify',{challenge_id:laterOptions.challenge_id,
    response:passkey.assertion(laterOptions.optionsJSON.challenge,3)},laterFlow);
  assert.equal(denied.status,400,'revoked passkeys cannot log in again');
});
