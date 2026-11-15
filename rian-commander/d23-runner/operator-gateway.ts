
import { createHmac,createHash,randomBytes,scryptSync,timingSafeEqual } from "node:crypto";
const env=Bun.env;
const origin=(env.RIAN_GATEWAY_PUBLIC_URL||"").replace(/\/+$/,"");
const resource=origin+"/mcp",masterSecret=env.RIAN_OAUTH_SIGNING_SECRET||"",secret=createHmac("sha256",masterSecret).update("rian-d23-operator-v1").digest("base64url"),pw=env.RIAN_OWNER_PASSWORD||"";
const backend=env.RIAN_D23_BROKER_URL||"",backendKey=env.RIAN_D23_OPERATOR_TOKEN||"",approvalKey=env.RIAN_D23_APPROVER_TOKEN||"";
const readback=env.RIAN_FLEET_READBACK_URL||"",readbackKey=env.RIAN_FLEET_READBACK_TOKEN||"";
const authReady=origin.startsWith("https://")&&masterSecret.length>=43&&pw.length>=20,bridgeReady=backend==="https://rian-d23-restricted-broker-production.up.railway.app"&&backendKey.length>=48&&approvalKey.length>=48&&readback==="https://rian-commander-relay-production.up.railway.app/mcp/gateway-readonly"&&readbackKey.length>=48;
const pwHash=authReady?scryptSync(pw,createHash("sha256").update("rian-commander-owner-password-v1:"+secret).digest().subarray(0,16),32):null;
const devices=["DESKTOP-EEMFO3L","DESKTOP-1QGT8D6","DESKTOP-S0UV4D1","Oui-MacStudio.local"];
const codes=new Map(),refreshSpent=new Map(),loginFailures=new Map();
const now=()=>Math.floor(Date.now()/1000),b64=v=>Buffer.from(v).toString("base64url"),un64=v=>Buffer.from(v,"base64url").toString("utf8"),rand=n=>randomBytes(n||32).toString("base64url");
const sign=v=>b64(createHmac("sha256",secret).update(v).digest());
const eq=(a,b)=>{let x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y)};
function ticket(x){let raw=b64(JSON.stringify(x));return raw+"."+sign(raw)}
function unticket(v){if(typeof v!=="string"||v.length>10000||!/^[\w-]+\.[\w-]+$/.test(v))return null;let i=v.lastIndexOf("."),a=v.slice(0,i);if(!eq(sign(a),v.slice(i+1)))return null;try{let x=JSON.parse(un64(a));return x.exp>now()?x:null}catch{return null}}
function jwt(claims,ttl){let h=b64(JSON.stringify({alg:"HS256",typ:"JWT"})),b=b64(JSON.stringify({...claims,iss:origin,iat:now(),exp:now()+ttl}));return h+"."+b+"."+sign(h+"."+b)}
function decodeJWT(v){if(typeof v!=="string"||v.length>12000)return null;let a=v.split(".");if(a.length!==3||!eq(sign(a[0]+"."+a[1]),a[2]))return null;try{let h=JSON.parse(un64(a[0])),j=JSON.parse(un64(a[1]));return h.alg==="HS256"&&h.typ==="JWT"&&j.exp>now()&&j.iss===origin&&j.iat<=now()+60?j:null}catch{return null}}
function redirectOK(v){
 if(typeof v!=="string"||v.length>1024)return false;
 try{
  let u=new URL(v);
  if(u.username||u.password||u.search||u.hash)return false;
  if(u.protocol==="https:"&&u.hostname==="chatgpt.com"&&!u.port)
   return u.pathname==="/connector_platform_oauth_redirect"||/^\/connector\/oauth\/[\w-]+$/.test(u.pathname);
  if(u.protocol==="http:"&&u.hostname==="127.0.0.1")
   return /^\/callback(?:\/[\w-]+)?\/?$/.test(u.pathname);
  return false;
 }catch{return false}
}
function redirectMatches(registered,incoming){
 if(!redirectOK(registered)||!redirectOK(incoming))return false;
 if(registered===incoming)return true;
 try{
  const a=new URL(registered),b=new URL(incoming);
  return a.protocol==="http:"&&b.protocol==="http:"&&a.hostname==="127.0.0.1"&&b.hostname===a.hostname&&!a.port&&a.pathname===b.pathname;
 }catch{return false}
}
function client(id){if(typeof id!=="string"||!id.startsWith("rian.")||id.length>3000)return null;let j=unticket(id.slice(5));return j?.type==="client"&&Array.isArray(j.redirects)&&j.redirects.every(redirectOK)?j:null}
function res(v,status=200,extra={}){return Response.json(v,{status,headers:{"cache-control":"no-store",...extra}})}
function escape(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function html(body,status=200){return new Response('<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>RIAN Commander 로그인</title><style>body{background:#0b1423;color:#e3ebfa;font:16px system-ui;margin:0}main{max-width:460px;margin:9vh auto;padding:30px;background:#172840;border:1px solid #334965;border-radius:18px}p{color:#bac7dc;line-height:1.7}input,button{box-sizing:border-box;width:100%;padding:13px;border-radius:8px;font:inherit}input{border:1px solid #8ca0ba}button{background:#367afa;color:white;border:0;margin-top:18px;font-weight:600}</style><main>'+body+'</main></html>',{status,headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store","referrer-policy":"no-referrer","content-security-policy":"default-src 'none'; style-src 'unsafe-inline'; form-action 'self' http://127.0.0.1:* https://chatgpt.com; base-uri 'none'; frame-ancestors 'none'","x-content-type-options":"nosniff"}})}
const device="DESKTOP-1QGT8D6", task="D23_AUDIT_READONLY_V1";
const tools=[
 {name:"rian_d23_request_audit",description:"Request one strictly read-only GPU/process observation on 1Q. Human approval is required in a separate browser page; this tool NEVER approves or executes jobs.",inputSchema:{type:"object",properties:{},additionalProperties:false}},
 {name:"rian_d23_job_status",description:"Get status of a previously requested D23 read-only observation; use the returned job_id.",inputSchema:{type:"object",properties:{job_id:{type:"string",pattern:"^[A-Za-z0-9_-]{16,64}$"}},required:["job_id"],additionalProperties:false}},
 {name:"rian_d23_read_result",description:"Read the D23 audit result through the separate read-only fleet connector after the task is COMPLETE.",inputSchema:{type:"object",properties:{job_id:{type:"string",pattern:"^[A-Za-z0-9_-]{16,64}$"}},required:["job_id"],additionalProperties:false}}
];
function safeArgs(name,a){
 if(!tools.some(t=>t.name===name)||a===null||typeof a!=="object"||Array.isArray(a))throw Error("Unknown D23 tool");
 if(name==="rian_d23_request_audit"){if(Object.keys(a).length!==0)throw Error("Arguments denied");return {};}
 if(Object.keys(a).length!==1||typeof a.job_id!=="string"||!/^[A-Za-z0-9_-]{16,64}$/.test(a.job_id))throw Error("Invalid job reference");
 return {job_id:a.job_id};
}
async function brokerFetch(path,method="GET",body=null,approval=false){
 const bearer=approval?approvalKey:backendKey;
 const response=await fetch(backend+path,{method,redirect:"error",headers:{"authorization":"Bearer "+bearer,"content-type":"application/json","accept":"application/json"},...(body===null?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(10000)});
 const text=await response.text();if(text.length>30000)throw Error("Broker response too large");
 if(!response.ok)throw Error("Broker HTTP "+response.status);
 return JSON.parse(text);
}
async function inspect(job_id){
 if(!/^[A-Za-z0-9_-]{16,64}$/.test(job_id))throw Error("Invalid job");
 return brokerFetch("/v1/d23/jobs/"+encodeURIComponent(job_id));
}
async function sendBackend(name,args){
 if(name==="rian_d23_request_audit"){
  const r=await brokerFetch("/v1/d23/requests","POST",{device,task});
  if(r.state!=="PENDING_APPROVAL"||!(/^[A-Za-z0-9_-]{16,64}$/.test(r.job_id)))throw Error("Invalid broker job");
  return {content:[{type:"text",text:JSON.stringify({job_id:r.job_id,device,task,state:r.state,approval_url:origin+"/approve/"+r.job_id,expires_in_seconds:600,instruction:"Owner must open approval_url and approve in their browser. The agent cannot approve or trigger execution. 1Q runner picks up approved jobs only when its local polling task is enabled."})}]};
 }
 const j=await inspect(args.job_id);
 if(j.device!==device||j.task!==task)throw Error("Unexpected job scope");
 if(name==="rian_d23_job_status"){
  return {content:[{type:"text",text:JSON.stringify({job_id:j.id,state:j.state,device:j.device,task:j.task,result_file:j.result_path||null,approval_url:j.state==="PENDING_APPROVAL"?origin+"/approve/"+j.id:null})}]};
 }
 if(name==="rian_d23_read_result"){
  if(j.state!=="COMPLETE")throw Error("Job not complete");
  if(typeof j.result_path!=="string"||!/^status-\d{8}-\d{6}-[a-f0-9]{8}\.json$/.test(j.result_path))throw Error("Unsafe result path");
  const path="salpion-d23-readonly/"+j.result_path;
  const r=await fetch(readback,{method:"POST",redirect:"error",headers:{"authorization":"Bearer "+readbackKey,"content-type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/call",params:{name:"rian_fleet_read_file",arguments:{device,path}}}),signal:AbortSignal.timeout(32000)});
  if(!r.ok)throw Error("Read-only MCP HTTP "+r.status);
  const packet=await r.json();
  if(packet.error||packet.result?.isError)throw Error("Read-only MCP rejected file");
  const remote=JSON.parse(packet.result?.content?.[0]?.text||"{}");
  if(remote.ok!==true||typeof remote.result?.content!=="string")throw Error("Result not available");
  const parsed=JSON.parse(remote.result.content);
  if(parsed.device!==device||!parsed.request_nonce_hash||typeof parsed.gpu!=="object")throw Error("Invalid result structure");
  return {content:[{type:"text",text:JSON.stringify({job_id:j.id,device,state:j.state,checked_at:parsed.checked_at_utc,d23_training:parsed.d23_training,gpu:parsed.gpu,python_processes:parsed.python_processes,result_file:j.result_path})}]};
 }
 throw Error("Unknown tool");
}
function loginPage(t,msg=""){return html('<h1>RIAN D23 점검 요청 MCP</h1><p>이 연결은 1Q에서 정해진 GPU/프로세스 읽기 전용 점검을 요청하고 결과를 조회합니다. 승인은 별도 브라우저에서 비밀번호 확인 후에만 가능합니다. 임의 명령이나 학습 시작은 지원하지 않습니다.</p>'+(msg?'<p role="alert">'+escape(msg)+'</p>':"")+'<form method="POST" action="/oauth/approve"><input type="hidden" name="request" value="'+escape(t)+'"><label for="password">소유자 로그인 암호</label><input name="password" id="password" type="password" minlength="20" autocomplete="current-password" required><button type="submit">D23 점검 요청 연결 승인</button></form>')}
function jobApprovalPage(id,msg=""){
 const challenge=ticket({type:"d23-human-approval",job_id:id,exp:now()+300,nonce:rand(16)});
 return html('<h1>D23 점검 1회 승인</h1><p>대상: DESKTOP-1QGT8D6 / 작업: D23_AUDIT_READONLY_V1</p><p>GPU 메모리와 Python 프로세스만 조회합니다. 학습 실행·파일 수정·임의 명령은 수행하지 않습니다.</p>'+(msg?'<p role="alert">'+escape(msg)+'</p>':"")+'<form method="POST" action="/d23/approve"><input type="hidden" name="request" value="'+escape(challenge)+'"><label for="password">소유자 암호</label><input name="password" id="password" type="password" minlength="20" autocomplete="current-password" required><button type="submit">이 점검 1회를 승인</button></form>');
}
function passwordOK(provided){
 if(typeof provided!=="string"||provided.length<20||provided.length>=300)return false;
 const hashed=scryptSync(provided,createHash("sha256").update("rian-commander-owner-password-v1:"+secret).digest().subarray(0,16),32);
 return timingSafeEqual(hashed,pwHash);
}
async function form(req){let s=await req.text();if(s.length>10000)throw Error("large");return new URLSearchParams(s)}
function issue(clientId){let claims={sub:"rian-owner",scope:"d23:request",client_id:clientId,role:"d23-operator"};return {access_token:jwt({...claims,typ:"access",aud:resource},1800),token_type:"Bearer",expires_in:1800,scope:"d23:request",refresh_token:jwt({...claims,typ:"refresh",aud:origin+"/oauth/token",jti:rand(24)},86400)}}
function denied(){return res({error:"unauthorized",message:"OAuth sign-in required"},401,{"www-authenticate":'Bearer resource_metadata="'+origin+'/.well-known/oauth-protected-resource", scope="d23:request"'})}
const meta={issuer:origin,authorization_endpoint:origin+"/oauth/authorize",token_endpoint:origin+"/oauth/token",registration_endpoint:origin+"/oauth/register",response_types_supported:["code"],grant_types_supported:["authorization_code","refresh_token"],code_challenge_methods_supported:["S256"],token_endpoint_auth_methods_supported:["none"],scopes_supported:["d23:request","offline_access"],authorization_response_iss_parameter_supported:true,client_id_metadata_document_supported:false};
Bun.serve({hostname:"0.0.0.0",port:Number(env.PORT||3000),async fetch(req){
 let u=new URL(req.url),p=u.pathname,m=req.method;
 if(p==="/health"&&m==="GET")return res({alive:true,version:"0.5.0",oauth_configured:authReady,backend_configured:bridgeReady,ready:authReady&&bridgeReady,read_only:false,audit_request_only:true,human_approval_required:true});
 if(p==="/"&&m==="GET")return html("<h1>RIAN Commander</h1><p>ChatGPT D23 읽기 전용 점검 요청 MCP. 브라우저 별도 승인이 필요합니다.</p>");
 if(!authReady)return res({error:"OAuth setup incomplete"},503);
 if((p==="/.well-known/oauth-protected-resource"||p==="/.well-known/oauth-protected-resource/mcp")&&m==="GET")return res({resource,authorization_servers:[origin],scopes_supported:["d23:request","offline_access"]});
 if((p==="/.well-known/oauth-authorization-server"||p==="/.well-known/openid-configuration")&&m==="GET")return res(meta);
 if(/^\/approve\/[A-Za-z0-9_-]{16,64}$/.test(p)&&m==="GET"){
  if(!bridgeReady)return html("<h1>점검 서버 연결 실패</h1>",503);
  const id=p.slice("/approve/".length);
  try{const job=await inspect(id);
   if(job.state!=="PENDING_APPROVAL"||job.device!==device||job.task!==task)return html("<h1>승인 대기가 아닙니다.</h1><p>이미 승인됐거나 만료된 작업입니다.</p>",409);
   return jobApprovalPage(id);
  }catch{return html("<h1>작업 조회 실패</h1>",404)}
 }
 if(p==="/d23/approve"&&m==="POST"){
  if(!bridgeReady)return html("<h1>점검 서버 연결 실패</h1>",503);
  const originHeader=req.headers.get("origin");
  if(originHeader&&originHeader!==origin)return html("<h1>접근 거부</h1>",403);
  const f=await form(req),t=unticket(f.get("request")||"");
  if(!t||t.type!=="d23-human-approval"||typeof t.job_id!=="string"||!/^[A-Za-z0-9_-]{16,64}$/.test(t.job_id))return html("<h1>만료되거나 잘못된 승인입니다.</h1>",400);
  const ip=(req.headers.get("cf-connecting-ip")||req.headers.get("x-forwarded-for")||"global").split(",")[0].slice(0,60),key="d23-approval:"+ip;
  let failure=loginFailures.get(key)||{count:0,until:now()+600};if(failure.until<now())failure={count:0,until:now()+600};
  if(failure.count>=6)return html("<h1>암호 시도 횟수 초과</h1>",429);
  if(!passwordOK(f.get("password")||"")){failure.count++;loginFailures.set(key,failure);return html("<h1>암호가 올바르지 않습니다.</h1><p>원래 승인 링크를 다시 여세요.</p>",401)}
  loginFailures.delete(key);
  try{const job=await inspect(t.job_id);
   if(job.state!=="PENDING_APPROVAL"||job.device!==device||job.task!==task)return html("<h1>승인 대기가 아닙니다.</h1>",409);
   const approved=await brokerFetch("/v1/d23/approve","POST",{job_id:t.job_id},true);
   if(approved.state!=="APPROVED")throw Error("Approval failed");
   return html('<h1>점검 승인 완료</h1><p>이 작업 1회만 승인됐습니다. 1Q의 등록된 점검 Runner가 실행하면 ChatGPT에서 결과를 조회할 수 있습니다.</p>');
  }catch{return html("<h1>점검 승인 실패 또는 만료</h1>",409)}
 }
 if(p==="/oauth/register"&&m==="POST"){
  let data;try{let x=await req.text();if(x.length>7000)throw Error();data=JSON.parse(x)}catch{return res({error:"invalid_client_metadata"},400)}
  if(!Array.isArray(data.redirect_uris)||!data.redirect_uris.length||data.redirect_uris.length>5||!data.redirect_uris.every(redirectOK)||(data.token_endpoint_auth_method&&data.token_endpoint_auth_method!=="none")){
   const uris=Array.isArray(data.redirect_uris)?data.redirect_uris.slice(0,8):[];
   console.info("RIAN_OAUTH_REGISTRATION_REJECT",JSON.stringify({uriCount:uris.length,callbacks:uris.map(x=>{try{let u=new URL(x);return {scheme:u.protocol,host:u.hostname,path:u.pathname,portPresent:!!u.port}}catch{return {malformed:true}}}),authMethod:data.token_endpoint_auth_method||"default"}));
   return res({error:"invalid_client_metadata"},400);
  }
  let id="rian."+ticket({type:"client",redirects:[...new Set(data.redirect_uris)],exp:now()+315360000,nonce:rand(12)});
  return res({client_id:id,client_id_issued_at:now(),redirect_uris:data.redirect_uris,grant_types:["authorization_code","refresh_token"],response_types:["code"],token_endpoint_auth_method:"none",client_name:"RIAN D23 Audit Operator MCP"},201);
 }
 if(p==="/oauth/authorize"&&m==="GET"){
  let q=u.searchParams,cid=q.get("client_id")||"",cli=client(cid),redirect=q.get("redirect_uri")||"",challenge=q.get("code_challenge")||"",scope=q.get("scope")||"",resourceClaim=q.get("resource")||"",state=q.get("state")||"";
  let sc=scope.split(/\s+/).filter(Boolean);
  if(!cli||!cli.redirects.some(x=>redirectMatches(x,redirect))||q.get("response_type")!=="code"||!sc.includes("d23:request")||sc.some(x=>!["d23:request","offline_access"].includes(x))||q.get("code_challenge_method")!=="S256"||!/^[\w-]{43}$/.test(challenge)||resourceClaim!==resource||state.length>2048)return html("<h1>잘못된 연결 요청</h1><p>ChatGPT OAuth 등록과 PKCE 값을 확인해 주세요.</p>",400);
  return loginPage(ticket({type:"authorization",exp:now()+300,client_id:cid,redirect,scope:sc.join(" "),challenge,resource:resourceClaim,state}));
 }
 if(p==="/oauth/approve"&&m==="POST"){
  let f;try{f=await form(req)}catch{return html("Invalid",400)}
  let request=f.get("request")||"",saved=unticket(request),cli=saved&&client(saved.client_id);
  if(!saved||saved.type!=="authorization"||saved.resource!==resource||!cli||!cli.redirects.some(x=>redirectMatches(x,saved.redirect)))return html("<p>승인 요청이 만료되었습니다. ChatGPT에서 다시 연결하세요.</p>",400);
  let ip=(req.headers.get("cf-connecting-ip")||req.headers.get("x-forwarded-for")||"global").split(",")[0].slice(0,60),key="login:"+ip;
  let fail=loginFailures.get(key)||{count:0,until:now()+600};if(fail.until<now())fail={count:0,until:now()+600};
  if(fail.count>=6)return html("<p>로그인 시도가 많아 차단됐습니다.</p>",429);
  let provided=f.get("password")||"",ok=false;
  if(provided.length>=20&&provided.length<300){let hash=scryptSync(provided,createHash("sha256").update("rian-commander-owner-password-v1:"+secret).digest().subarray(0,16),32);ok=timingSafeEqual(hash,pwHash)}
  if(!ok){fail.count++;loginFailures.set(key,fail);return loginPage(request,"암호가 일치하지 않습니다.")}
  loginFailures.delete(key);let code=rand(32);codes.set(code,{...saved,exp:now()+90});let callback=new URL(saved.redirect);callback.searchParams.set("code",code);if(saved.state)callback.searchParams.set("state",saved.state);callback.searchParams.set("iss",origin);
  return new Response(null,{status:302,headers:{"location":callback.toString(),"cache-control":"no-store","referrer-policy":"no-referrer"}});
 }
 if(p==="/oauth/token"&&m==="POST"){
  let f;try{f=await form(req)}catch{return res({error:"invalid_request"},400)}
  let cid=f.get("client_id")||"";if(!client(cid))return res({error:"invalid_client"},401);
  if(f.get("grant_type")==="authorization_code"){
   let code=f.get("code")||"",v=f.get("code_verifier")||"",c=codes.get(code);codes.delete(code);
   let challenge=createHash("sha256").update(v).digest("base64url");
   if(!c||c.exp<=now()||c.client_id!==cid||c.redirect!==f.get("redirect_uri")||c.resource!==f.get("resource")||!/^[A-Za-z0-9_.~-]{43,128}$/.test(v)||!eq(challenge,c.challenge))return res({error:"invalid_grant"},400);
   return res(issue(cid));
  }
  if(f.get("grant_type")==="refresh_token"){
   let token=decodeJWT(f.get("refresh_token")||"");
   if(!token||token.typ!=="refresh"||token.aud!==origin+"/oauth/token"||token.client_id!==cid||token.scope!=="d23:request"||refreshSpent.has(token.jti)||typeof token.jti!=="string"||f.get("resource")&&f.get("resource")!==resource)return res({error:"invalid_grant"},400);
   refreshSpent.set(token.jti,token.exp);return res(issue(cid));
  }
  return res({error:"unsupported_grant_type"},400)
 }
 if(p==="/mcp"&&(m==="GET"||m==="POST")){
  if(!bridgeReady)return res({error:"Backend unavailable"},503);
  let authorization=req.headers.get("authorization")||"",token=decodeJWT(authorization.startsWith("Bearer ")?authorization.slice(7):"");
  if(!token||token.typ!=="access"||token.aud!==resource||token.sub!=="rian-owner"||token.scope!=="d23:request"||!client(token.client_id))return denied();
  if(m==="GET")return new Response(null,{status:405,headers:{"allow":"POST","cache-control":"no-store"}});
  let x;try{let raw=await req.text();if(raw.length>64000)throw Error();x=JSON.parse(raw)}catch{return res({error:"Invalid JSON"},400)}
  if(x.method==="notifications/initialized")return new Response(null,{status:202});
  let result,id=x.id??null;
  if(x.method==="initialize")result={protocolVersion:"2025-03-26",capabilities:{tools:{}},serverInfo:{name:"rian-d23-operator",version:"1.0.0"}};
  else if(x.method==="tools/list")result={tools};
  else if(x.method==="ping")result={};
  else if(x.method==="tools/call"){try{let name=x.params?.name,args=safeArgs(name,x.params?.arguments||{});result=await sendBackend(name,args)}catch(err){result={isError:true,content:[{type:"text",text:String(err.message).slice(0,180)}]}}}
  else return res({jsonrpc:"2.0",id,error:{code:-32601,message:"Unknown method"}});
  return res({jsonrpc:"2.0",id,result});
 }
 return res({error:"Not found"},404)
}});
