
import { createHmac,createHash,randomBytes,scryptSync,timingSafeEqual } from "node:crypto";
const env=Bun.env;
const origin=(env.RIAN_GATEWAY_PUBLIC_URL||"").replace(/\/+$/,"");
const resource=origin+"/mcp",masterSecret=env.RIAN_OAUTH_SIGNING_SECRET||"",secret=createHmac("sha256",masterSecret).update("rian-eemf-owner-operator-v1").digest("base64url"),pw=env.RIAN_OWNER_PASSWORD||"";
const backend=env.RIAN_EEMF_BACKEND_URL||"",backendKey=env.RIAN_EEMF_GATEWAY_TOKEN||"",execProofKey=env.RIAN_EEMF_APPROVAL_SECRET||"";
const authReady=origin.startsWith("https://")&&masterSecret.length>=43&&pw.length>=20,bridgeReady=backend==="https://rian-commander-relay-production.up.railway.app/mcp/eemf-owner"&&backendKey.length>=48&&execProofKey.length>=48;
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
function html(body,status=200,referrerPolicy="no-referrer"){return new Response('<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="'+referrerPolicy+'"><title>RIAN Commander 로그인</title><style>body{background:#0b1423;color:#e3ebfa;font:16px system-ui;margin:0}main{max-width:460px;margin:9vh auto;padding:30px;background:#172840;border:1px solid #334965;border-radius:18px}p{color:#bac7dc;line-height:1.7}input,button{box-sizing:border-box;width:100%;padding:13px;border-radius:8px;font:inherit}input{border:1px solid #8ca0ba}button{background:#367afa;color:white;border:0;margin-top:18px;font-weight:600}</style><main>'+body+'</main></html>',{status,headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store","referrer-policy":referrerPolicy,"content-security-policy":"default-src 'none'; style-src 'unsafe-inline'; form-action 'self' http://127.0.0.1:* https://chatgpt.com; base-uri 'none'; frame-ancestors 'none'","x-content-type-options":"nosniff"}})}
const device="DESKTOP-EEMFO3L";
const tools=[
{name:"rian_eemf_status",description:"Read EEMFO3L current status only",inputSchema:{type:"object",properties:{},additionalProperties:false}},
{name:"rian_eemf_list_directory",description:"List EEMFO3L allowed relative home folder",inputSchema:{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false}},
{name:"rian_eemf_read_file",description:"Read UTF-8 text within EEMFO3L allowed home root",inputSchema:{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false}},
{name:"rian_eemf_request_command",description:"DRAFT a command execution on EEMFO3L requiring a separate explicit browser approval. Does not execute yet.",inputSchema:{type:"object",properties:{argv:{type:"array",items:{type:"string"}},cwd:{type:"string"},timeout:{type:"integer"}},required:["argv"],additionalProperties:false}},
{name:"rian_eemf_request_write",description:"DRAFT a write to a permitted text file on EEMFO3L requiring browser approval. Does not write yet.",inputSchema:{type:"object",properties:{path:{type:"string"},content:{type:"string"},overwrite:{type:"boolean"}},required:["path","content"],additionalProperties:false}},
{name:"rian_eemf_request_trusted_session",description:"Request a 30-minute read-only Proton local mail status/search session requiring a separate owner password approval. No write, sync or arbitrary commands.",inputSchema:{type:"object",properties:{},additionalProperties:false}},
{name:"rian_eemf_trusted_session_status",description:"Check your specific session state, expiry and remaining calls.",inputSchema:{type:"object",properties:{session_id:{type:"string",pattern:"^[A-Za-z0-9_-]{32,64}$"}},required:["session_id"],additionalProperties:false}},
{name:"rian_eemf_run_trusted_command",description:"Execute ONLY fixed Proton local status or subject-search commands within an approved time-limited session.",inputSchema:{type:"object",properties:{session_id:{type:"string",pattern:"^[A-Za-z0-9_-]{32,64}$"},argv:{type:"array",items:{type:"string"}},cwd:{type:"string"},timeout:{type:"integer"}},required:["session_id","argv","cwd"],additionalProperties:false}},
{name:"rian_eemf_revoke_trusted_session",description:"Revoke your active read-only trusted session immediately.",inputSchema:{type:"object",properties:{session_id:{type:"string",pattern:"^[A-Za-z0-9_-]{32,64}$"}},required:["session_id"],additionalProperties:false}},
{name:"rian_eemf_action_status",description:"Inspect a previously requested action result using the returned action_id",inputSchema:{type:"object",properties:{action_id:{type:"string"}},required:["action_id"],additionalProperties:false}}
];
const actionQueue=new Map();
const trustedSessions=new Map();
const TRUSTED_PROFILE="proton-local-readonly-v1";
const TRUSTED_CWD="Documents/RIAN-Proton-Tools";
const TRUSTED_SOURCE=TRUSTED_CWD+"/proton_mail_query.py";
const TRUSTED_DURATION_SECONDS=1800, TRUSTED_MAX_CALLS=60, TRUSTED_REQUEST_TTL=300;
const validSessionId=v=>typeof v==="string"&&/^[A-Za-z0-9_-]{32,64}$/.test(v);
function ownedSession(id,clientId){
 if(!validSessionId(id)||!clientId)throw Error("Invalid session");
 const session=trustedSessions.get(id);
 if(!session||session.clientId!==clientId)throw Error("Unknown trusted session");
 return session;
}
function currentSessionState(session,at=now()){
 if(session.state==="PENDING_APPROVAL"&&session.requestUntil<=at)session.state="EXPIRED";
 if(session.state==="ACTIVE"&&(session.validUntil<=at||session.remaining<=0))session.state="EXPIRED";
 return session.state;
}
export function validateTrustedMailCommand(raw){
 if(!raw||typeof raw!=="object"||Array.isArray(raw)||Object.keys(raw).some(k=>!["argv","cwd","timeout"].includes(k)))throw Error("Unapproved command fields");
 if(raw.cwd!==TRUSTED_CWD)throw Error("Trusted workspace only");
 const argv=raw.argv;
 if(!Array.isArray(argv)||argv.length<3||argv.length>6||argv.some(x=>typeof x!=="string"||!x||x.length>120||/[\x00-\x1f\x7f]/.test(x)))throw Error("Invalid argv");
 if(argv[0]!=="python"||argv[1]!=="proton_mail_query.py")throw Error("Command not in trusted allowlist");
 if(argv[2]==="status"){
  if(argv.length!==3)throw Error("Unexpected status arguments");
 }else if(argv[2]==="search"){
  if(argv.length!==4&&argv.length!==6)throw Error("Invalid search command");
  if(!argv[3].trim()||argv[3].startsWith("-"))throw Error("Invalid search query");
  if(argv.length===6&&(argv[4]!=="--limit"||!/^\d{1,2}$/.test(argv[5])||Number(argv[5])<1||Number(argv[5])>20))throw Error("Search limit denied");
 }else throw Error("Only local Proton subject search and status are trusted");
 const timeout=raw.timeout===undefined?30:raw.timeout;
 if(!Number.isInteger(timeout)||timeout<1||timeout>45)throw Error("Trusted timeout denied");
 return {argv:[...argv],cwd:TRUSTED_CWD,timeout};
}
async function trustedSourceDigest(){
 const fileResult=await relay("rian_eemf_read_file",{path:TRUSTED_SOURCE});
 const content=fileResult?.result?.content;
 if(typeof content!=="string"||content.length<50||content.length>25000)throw Error("Trusted script unavailable");
 return createHash("sha256").update(content,"utf8").digest("hex");
}
function sessionSummary(id,session){
 return {session_id:id,device,profile:TRUSTED_PROFILE,state:currentSessionState(session),expires_at:session.validUntil||null,remaining_calls:session.remaining,maximum_calls:TRUSTED_MAX_CALLS,workspace:TRUSTED_CWD};
}

function safePath(value){
 if(typeof value!=="string"||value.length>512||!value.trim()||/[\x00-\x1f]/.test(value))throw Error("Invalid path");
 const path=value.replaceAll("\\","/");
 if(path.startsWith("/")||path.startsWith("~")||path.includes(":")||path.split("/").some(x=>x===".."))throw Error("Path outside allowed root");
 const segments=path.toLowerCase().split("/");
 const banned=[".ssh",".aws",".kube",".gnupg",".codex",".claude",".git","appdata","credentials","secrets",".env","ntuser.dat"];
 if(segments.some(x=>banned.includes(x)||x.endsWith(".pfx")||x.endsWith(".pem")||x.endsWith(".key")))throw Error("Sensitive path denied");
 return path;
}
function safeArgs(name,args){
 if(!tools.some(x=>x.name===name)||!args||typeof args!=="object"||Array.isArray(args))throw Error("Tool denied");
 if(name==="rian_eemf_status"){if(Object.keys(args).length)throw Error("Unexpected args");return {};}
 if(name==="rian_eemf_list_directory"||name==="rian_eemf_read_file"){
  if(Object.keys(args).length!==1||!Object.hasOwn(args,"path"))throw Error("Unexpected args");
  return {path:safePath(args.path)};
 }
 if(name==="rian_eemf_request_trusted_session"){
  if(Object.keys(args).length)throw Error("Unexpected trusted session parameters");
  return {};
 }
 if(name==="rian_eemf_trusted_session_status"||name==="rian_eemf_revoke_trusted_session"){
  if(Object.keys(args).length!==1||!validSessionId(args.session_id))throw Error("Invalid trusted session ID");
  return {session_id:args.session_id};
 }
 if(name==="rian_eemf_run_trusted_command"){
  if(Object.keys(args).some(k=>!["session_id","argv","cwd","timeout"].includes(k))||!validSessionId(args.session_id))throw Error("Invalid trusted request");
  const {session_id,...command}=args;
  return {session_id,...validateTrustedMailCommand(command)};
 }
 if(name==="rian_eemf_action_status"){
  if(Object.keys(args).length!==1||typeof args.action_id!=="string"||!/^[A-Za-z0-9_-]{32,64}$/.test(args.action_id))throw Error("Invalid action reference");
  return {action_id:args.action_id};
 }
 if(name==="rian_eemf_request_write"){
  if(Object.keys(args).some(x=>!["path","content","overwrite"].includes(x)))throw Error("Unexpected args");
  if(typeof args.content!=="string"||args.content.length>12000||args.content.includes("\0"))throw Error("Invalid write content");
  return {path:safePath(args.path),content:args.content,overwrite:args.overwrite===true};
 }
 if(name==="rian_eemf_request_command"){
  if(Object.keys(args).some(x=>!["argv","cwd","timeout"].includes(x)))throw Error("Unexpected args");
  if(!Array.isArray(args.argv)||args.argv.length<1||args.argv.length>20||args.argv.some(x=>typeof x!=="string"||!x.length||x.length>500||/[\x00-\x1f]/.test(x)))throw Error("Invalid argv");
  if(args.cwd!==undefined&&typeof args.cwd!=="string")throw Error("Invalid cwd");
  const cwd=args.cwd?safePath(args.cwd):undefined;
  const timeout=Number.isInteger(args.timeout)?args.timeout:30;
  if(timeout<1||timeout>90)throw Error("Timeout denied");
  return {argv:args.argv,cwd,timeout};
 }
 throw Error("Unknown tool");
}
async function relay(name,args,ownerApproved=false){
 const headers={"authorization":"Bearer "+backendKey,"content-type":"application/json"};
 if(ownerApproved){
  if(name!=="rian_eemf_run_command"&&name!=="rian_eemf_write_file")throw Error("Invalid privileged action");
  const claim={name,exp:now()+45,nonce:randomBytes(16).toString("hex"),sha256:createHash("sha256").update(JSON.stringify(args)).digest("hex")};
  const packed=Buffer.from(JSON.stringify(claim)).toString("base64url");
  headers["x-rian-eemf-approved"]=packed+"."+createHmac("sha256",execProofKey).update(packed).digest("hex");
 }
 const r=await fetch(backend,{method:"POST",redirect:"error",headers,body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/call",params:{name,arguments:args}}),signal:AbortSignal.timeout(42000)});
 if(!r.ok)throw Error("Relay HTTP "+r.status);
 const v=await r.json();if(v.error||v.result?.isError)throw Error("Relay denied");
 let parsed;
 try{parsed=JSON.parse(v.result?.content?.[0]?.text||"{}")}catch{throw Error("Invalid relay result")}
 if(parsed.ok!==true)throw Error("EEMFO3L agent rejected the operation");
 return parsed;
}
function sessionReply(value){return {content:[{type:"text",text:JSON.stringify(value)}]}}
function newTrustedSession(clientId){
 if(typeof clientId!=="string"||!clientId.startsWith("rian."))throw Error("Authenticated client required");
 for(const [id,s] of trustedSessions){
  const state=currentSessionState(s);
  if(s.clientId===clientId&&(state==="PENDING_APPROVAL"||state==="ACTIVE"))throw Error("Existing pending or active trusted session: "+id);
 }
 if(trustedSessions.size>=40){
  for(const [id,s] of trustedSessions){if(["EXPIRED","REVOKED"].includes(currentSessionState(s)))trustedSessions.delete(id)}
 }
 if(trustedSessions.size>=40)throw Error("Trusted session capacity reached");
 const id=rand(32);
 trustedSessions.set(id,{clientId,state:"PENDING_APPROVAL",requestUntil:now()+TRUSTED_REQUEST_TTL,validUntil:null,remaining:0,sourceHash:null,busy:false,attempts:0});
 return sessionReply({session_id:id,state:"PENDING_APPROVAL",device,profile:TRUSTED_PROFILE,approval_url:origin+"/session/approve/"+id,request_expires_in:TRUSTED_REQUEST_TTL,duration_after_approval_seconds:TRUSTED_DURATION_SECONDS,maximum_calls:TRUSTED_MAX_CALLS,warning:"Requires owner password in browser; no commands execute before approval."});
}
async function trustedDispatch(name,args,clientId){
 if(name==="rian_eemf_request_trusted_session")return newTrustedSession(clientId);
 const s=ownedSession(args.session_id,clientId),state=currentSessionState(s);
 if(name==="rian_eemf_trusted_session_status")return sessionReply(sessionSummary(args.session_id,s));
 if(name==="rian_eemf_revoke_trusted_session"){
  s.state="REVOKED";s.remaining=0;
  return sessionReply(sessionSummary(args.session_id,s));
 }
 if(name!=="rian_eemf_run_trusted_command")throw Error("Unsupported session action");
 if(state!=="ACTIVE"||s.remaining<=0)throw Error("Trusted session inactive or expired; browser reapproval required");
 if(s.busy)throw Error("Trusted session busy; concurrent commands are not allowed");
 // Validate twice: tool arguments were previously checked; guard again at authorization.
 const {session_id, ...raw}=args;
 const safe=validateTrustedMailCommand(raw);
 s.busy=true;
 try{
  const digest=await trustedSourceDigest();
  if(s.sourceHash!==digest){s.state="REVOKED";s.remaining=0;throw Error("Trusted script changed; session revoked")};
  if(currentSessionState(s)!=="ACTIVE")throw Error("Trusted session no longer active");
  // Consume a quota unit before submitting so failures cannot evade limits.
  s.remaining--;
  const out=await relay("rian_eemf_run_command",safe,true);
  return sessionReply({session_id,device,profile:TRUSTED_PROFILE,state:currentSessionState(s),remaining_calls:s.remaining,command:safe.argv,execution:out});
 }finally{s.busy=false}
}
async function sendBackend(name,args,clientId){
 if(name==="rian_eemf_request_trusted_session"||name==="rian_eemf_trusted_session_status"||name==="rian_eemf_run_trusted_command"||name==="rian_eemf_revoke_trusted_session")return trustedDispatch(name,args,clientId);
 if(name==="rian_eemf_status"||name==="rian_eemf_list_directory"||name==="rian_eemf_read_file"){
  const target=name;
  const val=await relay(target,args);
  if(JSON.stringify(val).length>100000)throw Error("Result too large");
  return {content:[{type:"text",text:JSON.stringify(val)}]};
 }
 if(name==="rian_eemf_action_status"){
  const a=actionQueue.get(args.action_id);
  if(!a||a.exp<now())throw Error("Unknown or expired action");
  return {content:[{type:"text",text:JSON.stringify({action_id:args.action_id,status:a.status,device,completed:a.done||null,summary:a.summary||null})}]};
 }
 const actionId=rand(32);
 if(actionQueue.size>80){for(const [id,x] of actionQueue){if(x.exp<now()||x.status==="COMPLETE")actionQueue.delete(id)}}
 if(actionQueue.size>80)throw Error("Action queue full");
 const operation=name==="rian_eemf_request_command"?"rian_eemf_run_command":"rian_eemf_write_file";
 actionQueue.set(actionId,{operation,args,status:"PENDING_APPROVAL",exp:now()+300});
 return {content:[{type:"text",text:JSON.stringify({action_id:actionId,device,status:"PENDING_APPROVAL",preview:operation==="rian_eemf_run_command"?{argv:args.argv,cwd:args.cwd||null,timeout:args.timeout}:{path:args.path,overwrite:args.overwrite,contentLength:args.content.length},approval_url:origin+"/approve/"+actionId,expires_in_seconds:300,note:"No command or write was executed. Open the separate approval URL, review the exact action, and confirm with owner password."})}]};
}
function loginPage(ticketData,msg=""){return html('<h1>RIAN Commander — EEMFO3L 운영 연결</h1><p>이 서버는 EEMFO3L 파일 조회를 제공하고, 명령 실행과 파일 수정은 건별로 별도 브라우저 승인을 요구합니다. 다른 PC 실행 권한은 제공하지 않습니다.</p>'+(msg?'<p role="alert">'+escape(msg)+'</p>':"")+'<form method="POST" action="/oauth/approve"><input type="hidden" name="request" value="'+escape(ticketData)+'"><label for="password">소유자 암호</label><input name="password" id="password" type="password" minlength="20" autocomplete="current-password" required><button type="submit">EEMF 운영 연결 승인</button></form>')}
function passwordOK(provided){
 if(typeof provided!=="string"||provided.length<20||provided.length>=300)return false;
 const hash=scryptSync(provided,createHash("sha256").update("rian-commander-owner-password-v1:"+secret).digest().subarray(0,16),32);
 return timingSafeEqual(hash,pwHash);
}
function actionPage(id,item,msg=""){
 const description=item.operation==="rian_eemf_run_command"?JSON.stringify({argv:item.args.argv,cwd:item.args.cwd||null,timeout:item.args.timeout},null,2):JSON.stringify({path:item.args.path,overwrite:item.args.overwrite,content:item.args.content},null,2);
 const approval=ticket({type:"eemf-action-approval",id,exp:now()+240,nonce:rand(16)});
 return html('<h1>EEMFO3L 작업 승인</h1><p>대상 PC: DESKTOP-EEMFO3L</p><p>작업 내용을 반드시 검토하세요. 실행 또는 파일 변경은 승인 후에만 수행됩니다.</p><pre style="white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1423;padding:12px">'+escape(description)+'</pre>'+(msg?'<p role="alert">'+escape(msg)+'</p>':"")+'<form method="POST" action="/action/approve"><input type="hidden" name="request" value="'+escape(approval)+'"><label for="password">소유자 암호</label><input name="password" type="password" minlength="20" required><button type="submit">표시된 작업 1회 승인 및 실행</button></form>',200,"same-origin")
}
function trustedSessionPage(id,s){
 const nonce=ticket({type:"eemf-trusted-session-approval",id,exp:now()+240,nonce:rand(16)});
 return html('<h1>EEMFO3L 읽기 전용 세션 승인</h1>'+
 '<p>대상 장치: DESKTOP-EEMFO3L</p><p>프로필: Proton 로컬 메일 색인 상태와 제목 검색</p>'+
 '<p>허용: python proton_mail_query.py status / search TERM --limit 1..20</p>'+
 '<p>허용하지 않음: 메일 본문 읽기, 전체 검색, 파일 수정, 동기화, PowerShell 실행, 임의 스크립트, 다른 PC 제어</p>'+
 '<p>승인 후 30분 또는 최대 60회 중 먼저 도달한 조건에 따라 만료됩니다. ChatGPT에서 즉시 취소할 수 있습니다. 현재 소유자 암호는 이 세션 시작에만 사용합니다.</p>'+
 '<form method="POST" action="/session/activate"><input type="hidden" name="request" value="'+escape(nonce)+'">'+
 '<label for="password">소유자 암호</label><input id="password" name="password" type="password" autocomplete="current-password" minlength="20" required>'+
 '<button type="submit">이 범위의 읽기 전용 세션 승인</button></form>',200,"same-origin");
}
async function form(req){let s=await req.text();if(s.length>10000)throw Error("large");return new URLSearchParams(s)}
function issue(clientId){let claims={sub:"rian-owner",scope:"eemf:operate",client_id:clientId,role:"eemf-owner"};return {access_token:jwt({...claims,typ:"access",aud:resource},1800),token_type:"Bearer",expires_in:1800,scope:"eemf:operate",refresh_token:jwt({...claims,typ:"refresh",aud:origin+"/oauth/token",jti:rand(24)},86400)}}
function denied(){return res({error:"unauthorized",message:"OAuth sign-in required"},401,{"www-authenticate":'Bearer resource_metadata="'+origin+'/.well-known/oauth-protected-resource", scope="eemf:operate"'})}
const meta={issuer:origin,authorization_endpoint:origin+"/oauth/authorize",token_endpoint:origin+"/oauth/token",registration_endpoint:origin+"/oauth/register",response_types_supported:["code"],grant_types_supported:["authorization_code","refresh_token"],code_challenge_methods_supported:["S256"],token_endpoint_auth_methods_supported:["none"],scopes_supported:["eemf:operate","offline_access"],authorization_response_iss_parameter_supported:true,client_id_metadata_document_supported:false};
if(env.RIAN_TEST_MODE!=="1")Bun.serve({hostname:"0.0.0.0",port:Number(env.PORT||3000),async fetch(req){
 let u=new URL(req.url),p=u.pathname,m=req.method;
 if(p==="/health"&&m==="GET")return res({alive:true,version:"0.5.0",oauth_configured:authReady,backend_configured:bridgeReady,ready:authReady&&bridgeReady,read_only:false,manual_approval_required:true,device_only:"DESKTOP-EEMFO3L"});
 if(p==="/"&&m==="GET")return html("<h1>RIAN Commander</h1><p>ChatGPT 원격 MCP 연결. PC 조회를 위해 로그인 승인이 필요합니다.</p>");
 if(!authReady)return res({error:"OAuth setup incomplete"},503);
 if((p==="/.well-known/oauth-protected-resource"||p==="/.well-known/oauth-protected-resource/mcp")&&m==="GET")return res({resource,authorization_servers:[origin],scopes_supported:["eemf:operate","offline_access"]});
 if((p==="/.well-known/oauth-authorization-server"||p==="/.well-known/openid-configuration")&&m==="GET")return res(meta);
 if(/^\/session\/approve\/[A-Za-z0-9_-]{32,64}$/.test(p)&&m==="GET"){
  const id=p.slice("/session/approve/".length),s=trustedSessions.get(id);
  if(!s||currentSessionState(s)!=="PENDING_APPROVAL")return html("<h1>세션 요청이 만료되었거나 이미 처리되었습니다.</h1>",409);
  return trustedSessionPage(id,s);
 }
 if(p==="/session/activate"&&m==="POST"){
  const originHeader=req.headers.get("origin");
  if(originHeader!==origin)return html("<h1>다른 출처의 승인 요청 차단</h1>",403);
  let values;try{values=await form(req)}catch{return html("<h1>잘못된 승인 양식</h1>",400)}
  const proof=unticket(values.get("request")||"");
  if(!proof||proof.type!=="eemf-trusted-session-approval"||!validSessionId(proof.id))return html("<h1>승인 링크가 만료되었습니다.</h1>",400);
  const s=trustedSessions.get(proof.id);
  if(!s||currentSessionState(s)!=="PENDING_APPROVAL")return html("<h1>승인 대기 세션이 없습니다.</h1>",409);
  const ip=(req.headers.get("cf-connecting-ip")||req.headers.get("x-forwarded-for")||"global").split(",")[0].slice(0,60),key="eemf-trusted:"+ip;
  let failure=loginFailures.get(key)||{count:0,until:now()+600};
  if(failure.until<now())failure={count:0,until:now()+600};
  if(failure.count>=6)return html("<h1>암호 시도 횟수 초과</h1>",429);
  if(!passwordOK(values.get("password")||"")){failure.count++;loginFailures.set(key,failure);return html("<h1>소유자 암호 불일치</h1>",401)}
  loginFailures.delete(key);
  // Race-safe state switch: multiple overlapping approval POSTs cannot activate twice.
  s.state="VERIFYING";
  try{
   const sourceHash=await trustedSourceDigest();
   if(s.state!=="VERIFYING"||s.requestUntil<=now())throw Error("Approval expired or revoked");
   s.sourceHash=sourceHash;
   s.state="ACTIVE";s.validUntil=now()+TRUSTED_DURATION_SECONDS;s.remaining=TRUSTED_MAX_CALLS;
   return html("<h1>읽기 전용 세션 승인 완료</h1><p>DESKTOP-EEMFO3L Proton 색인 상태·제목 검색을 30분간 최대 60회 허용했습니다. ChatGPT에서 상태를 조회하고 필요 시 즉시 취소할 수 있습니다.</p>");
  }catch{
   s.state="REVOKED";s.remaining=0;
   return html("<h1>세션 활성화 실패</h1><p>원격 스크립트 무결성이나 PC 연결을 확인해야 합니다.</p>",409)
  }
 }
 if(/^\/approve\/[A-Za-z0-9_-]{32,64}$/.test(p)&&m==="GET"){
  const id=p.slice("/approve/".length),item=actionQueue.get(id);
  if(!item||item.exp<now()||item.status!=="PENDING_APPROVAL")return html("<h1>작업이 만료되거나 이미 처리되었습니다.</h1>",409);
  return actionPage(id,item);
 }
 if(p==="/action/approve"&&m==="POST"){
  let f;try{f=await form(req)}catch{return html("<h1>잘못된 승인</h1>",400)}
  const proof=unticket(f.get("request")||"");
  if(!proof||proof.type!=="eemf-action-approval"||typeof proof.id!=="string")return html("<h1>승인 요청 만료</h1>",400);
  const id=proof.id,item=actionQueue.get(id);
  if(!item||item.exp<now()||item.status!=="PENDING_APPROVAL")return html("<h1>작업 만료 또는 처리 완료</h1>",409);
  const originHeader=req.headers.get("origin");
  if(originHeader&&originHeader!==origin)return html("<h1>다른 출처의 요청 차단</h1>",403);
  const ip=(req.headers.get("cf-connecting-ip")||req.headers.get("x-forwarded-for")||"global").split(",")[0].slice(0,60),key="eemf-approval:"+ip;
  let failure=loginFailures.get(key)||{count:0,until:now()+600};if(failure.until<now())failure={count:0,until:now()+600};
  if(failure.count>=6)return html("<h1>암호 시도 횟수 초과</h1>",429);
  if(!passwordOK(f.get("password")||"")){failure.count++;loginFailures.set(key,failure);return html("<h1>암호 불일치</h1>",401)}
  loginFailures.delete(key);
  item.status="RUNNING";
  try{
   const r=await relay(item.operation,item.args,true);
   item.status="COMPLETE";item.done=now();
   item.summary=JSON.stringify(r).slice(0,30000);
   return html('<h1>작업 완료</h1><p>ChatGPT에서 작업 ID로 결과를 확인할 수 있습니다.</p>');
  }catch(err){
   item.status="FAILED";item.done=now();item.summary=String(err.message).slice(0,300);
   return html("<h1>실행 실패</h1><p>"+escape(item.summary)+"</p>",409)
  }
 }
 if(p==="/oauth/register"&&m==="POST"){
  let data;try{let x=await req.text();if(x.length>7000)throw Error();data=JSON.parse(x)}catch{return res({error:"invalid_client_metadata"},400)}
  if(!Array.isArray(data.redirect_uris)||!data.redirect_uris.length||data.redirect_uris.length>5||!data.redirect_uris.every(redirectOK)||(data.token_endpoint_auth_method&&data.token_endpoint_auth_method!=="none")){
   const uris=Array.isArray(data.redirect_uris)?data.redirect_uris.slice(0,8):[];
   console.info("RIAN_OAUTH_REGISTRATION_REJECT",JSON.stringify({uriCount:uris.length,callbacks:uris.map(x=>{try{let u=new URL(x);return {scheme:u.protocol,host:u.hostname,path:u.pathname,portPresent:!!u.port}}catch{return {malformed:true}}}),authMethod:data.token_endpoint_auth_method||"default"}));
   return res({error:"invalid_client_metadata"},400);
  }
  let id="rian."+ticket({type:"client",redirects:[...new Set(data.redirect_uris)],exp:now()+315360000,nonce:rand(12)});
  return res({client_id:id,client_id_issued_at:now(),redirect_uris:data.redirect_uris,grant_types:["authorization_code","refresh_token"],response_types:["code"],token_endpoint_auth_method:"none",client_name:"RIAN EEMF Owner Operator"},201);
 }
 if(p==="/oauth/authorize"&&m==="GET"){
  let q=u.searchParams,cid=q.get("client_id")||"",cli=client(cid),redirect=q.get("redirect_uri")||"",challenge=q.get("code_challenge")||"",scope=q.get("scope")||"",resourceClaim=q.get("resource")||"",state=q.get("state")||"";
  let sc=scope.split(/\s+/).filter(Boolean);
  if(!cli||!cli.redirects.some(x=>redirectMatches(x,redirect))||q.get("response_type")!=="code"||!sc.includes("eemf:operate")||sc.some(x=>!["eemf:operate","offline_access"].includes(x))||q.get("code_challenge_method")!=="S256"||!/^[\w-]{43}$/.test(challenge)||resourceClaim!==resource||state.length>2048)return html("<h1>잘못된 연결 요청</h1><p>ChatGPT OAuth 등록과 PKCE 값을 확인해 주세요.</p>",400);
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
   if(!token||token.typ!=="refresh"||token.aud!==origin+"/oauth/token"||token.client_id!==cid||token.scope!=="eemf:operate"||refreshSpent.has(token.jti)||typeof token.jti!=="string"||f.get("resource")&&f.get("resource")!==resource)return res({error:"invalid_grant"},400);
   refreshSpent.set(token.jti,token.exp);return res(issue(cid));
  }
  return res({error:"unsupported_grant_type"},400)
 }
 if(p==="/mcp"&&(m==="GET"||m==="POST")){
  if(!bridgeReady)return res({error:"Backend unavailable"},503);
  let authorization=req.headers.get("authorization")||"",token=decodeJWT(authorization.startsWith("Bearer ")?authorization.slice(7):"");
  if(!token||token.typ!=="access"||token.aud!==resource||token.sub!=="rian-owner"||token.scope!=="eemf:operate"||!client(token.client_id))return denied();
  if(m==="GET")return new Response(null,{status:405,headers:{"allow":"POST","cache-control":"no-store"}});
  let x;try{let raw=await req.text();if(raw.length>64000)throw Error();x=JSON.parse(raw)}catch{return res({error:"Invalid JSON"},400)}
  if(x.method==="notifications/initialized")return new Response(null,{status:202});
  let result,id=x.id??null;
  if(x.method==="initialize")result={protocolVersion:"2025-03-26",capabilities:{tools:{}},serverInfo:{name:"rian-eemf-owner",version:"1.0.0"}};
  else if(x.method==="tools/list")result={tools};
  else if(x.method==="ping")result={};
  else if(x.method==="tools/call"){try{let name=x.params?.name,args=safeArgs(name,x.params?.arguments||{});result=await sendBackend(name,args,token.client_id)}catch(err){result={isError:true,content:[{type:"text",text:String(err.message).slice(0,180)}]}}}
  else return res({jsonrpc:"2.0",id,error:{code:-32601,message:"Unknown method"}});
  return res({jsonrpc:"2.0",id,result});
 }
 return res({error:"Not found"},404)
}});
