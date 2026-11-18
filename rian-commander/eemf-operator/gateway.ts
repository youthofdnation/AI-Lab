
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
  if(u.protocol==="https:"&&(u.hostname==="claude.ai"||u.hostname==="claude.com")&&!u.port)
   return u.pathname==="/api/mcp/auth_callback";
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
function html(body,status=200,referrerPolicy="no-referrer"){return new Response('<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="'+referrerPolicy+'"><title>RIAN Commander 로그인</title><style>body{background:#0b1423;color:#e3ebfa;font:16px system-ui;margin:0}main{max-width:460px;margin:9vh auto;padding:30px;background:#172840;border:1px solid #334965;border-radius:18px}p{color:#bac7dc;line-height:1.7}input,select,button{box-sizing:border-box;width:100%;padding:13px;border-radius:8px;font:inherit}input,select{border:1px solid #8ca0ba}button{background:#367afa;color:white;border:0;margin-top:18px;font-weight:600}</style><main>'+body+'</main></html>',{status,headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store","referrer-policy":referrerPolicy,"content-security-policy":"default-src 'none'; style-src 'unsafe-inline'; form-action 'self' http://127.0.0.1:* https://chatgpt.com https://claude.ai https://claude.com; base-uri 'none'; frame-ancestors 'none'","x-content-type-options":"nosniff"}})}
const device="DESKTOP-EEMFO3L";
const tools=[
{name:"rian_eemf_status",description:"Read EEMFO3L current status only",inputSchema:{type:"object",properties:{},additionalProperties:false}},
{name:"rian_eemf_list_directory",description:"List EEMFO3L allowed relative home folder",inputSchema:{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false}},
{name:"rian_eemf_read_file",description:"Read UTF-8 text within EEMFO3L allowed home root",inputSchema:{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false}},
{name:"rian_eemf_request_command",description:"Request an EEMFO3L command; browser lets owner choose per-command or scoped timed approval (eligible safe read-only commands only). Eligible commands reuse active session unless approval_mode=each.",inputSchema:{type:"object",properties:{argv:{type:"array",items:{type:"string"}},cwd:{type:"string"},timeout:{type:"integer"},approval_mode:{type:"string",enum:["choose","each"]}},required:["argv"],additionalProperties:false}},
{name:"rian_eemf_request_write",description:"DRAFT a write to a permitted text file on EEMFO3L requiring browser approval. Does not write yet.",inputSchema:{type:"object",properties:{path:{type:"string"},content:{type:"string"},overwrite:{type:"boolean"}},required:["path","content"],additionalProperties:false}},
{name:"rian_eemf_request_trusted_session",description:"Request a user-selected 1-60 minute restricted trust session, owner password approval once: Proton title search, Outlook metadata search, or limited developer version checks. No writes or arbitrary shell.",inputSchema:{type:"object",properties:{profile:{type:"string",enum:["proton-local-readonly-v1","outlook-local-metadata-v1","dev-version-checks-v1","dev-sandbox-smoke-v1","dev-workspace-edit-v1"]}},additionalProperties:false}},
{name:"rian_eemf_trusted_session_status",description:"Check your specific session state, expiry and remaining calls.",inputSchema:{type:"object",properties:{session_id:{type:"string",pattern:"^[A-Za-z0-9_-]{32,64}$"}},required:["session_id"],additionalProperties:false}},
{name:"rian_eemf_run_trusted_command",description:"Execute fixed allowlisted Proton/Outlook queries or developer python/git/node --version after owner-scoped approval. No general shell, sync, file read/write.",inputSchema:{type:"object",properties:{session_id:{type:"string",pattern:"^[A-Za-z0-9_-]{32,64}$"},argv:{type:"array",items:{type:"string"}},cwd:{type:"string"},timeout:{type:"integer"}},required:["session_id","argv","cwd"],additionalProperties:false}},
{name:"rian_eemf_revoke_trusted_session",description:"Revoke your active read-only trusted session immediately.",inputSchema:{type:"object",properties:{session_id:{type:"string",pattern:"^[A-Za-z0-9_-]{32,64}$"}},required:["session_id"],additionalProperties:false}},
{name:"rian_eemf_action_status",description:"Inspect a previously requested action result using the returned action_id",inputSchema:{type:"object",properties:{action_id:{type:"string"}},required:["action_id"],additionalProperties:false}}
];
const actionQueue=new Map();
export const trustedSessions=new Map();
const TRUSTED_PROFILE="proton-local-readonly-v1";
const TRUSTED_CWD="Documents/RIAN-Proton-Tools";
const TRUSTED_SOURCE=TRUSTED_CWD+"/proton_mail_query.py";
const TRUSTED_DURATION_SECONDS=1800, TRUSTED_MAX_DURATION_SECONDS=3600, TRUSTED_MAX_CALLS=60, TRUSTED_REQUEST_TTL=300;
export function validDurationMinutes(v){return typeof v==="string"&&/^(?:[1-9]|[1-5]\d|60)$/.test(v)?Number(v):null;}
const OUTLOOK_PROFILE="outlook-local-metadata-v1";
const OUTLOOK_CWD="Documents/rian-outlook-bridge",OUTLOOK_SOURCE=OUTLOOK_CWD+"/outlook_bridge.py";
const SMOKE_PROFILE="dev-sandbox-smoke-v1",SMOKE_CWD="Documents",SMOKE_DIR="Documents/RIAN-Commander-Smoke";
const SMOKE_CALC=SMOKE_DIR+"/calculator.py",SMOKE_TEST_PATH=SMOKE_DIR+"/test_calculator.py";
const SMOKE_BUG="def total_with_tax(subtotal, tax_rate):\n    if subtotal < 0 or tax_rate < 0:\n        raise ValueError('negative inputs')\n    return subtotal - subtotal * tax_rate\n",SMOKE_FIXED="def total_with_tax(subtotal, tax_rate):\n    if subtotal < 0 or tax_rate < 0:\n        raise ValueError('negative inputs')\n    return subtotal + (subtotal * tax_rate)\n",SMOKE_TEST="import unittest\nfrom calculator import total_with_tax\n\nclass TaxTests(unittest.TestCase):\n    def test_tax_10(self):\n        self.assertEqual(total_with_tax(100, .1), 110)\n    def test_tax_25(self):\n        self.assertEqual(total_with_tax(80, .25), 100)\n    def test_zero(self):\n        self.assertEqual(total_with_tax(100, 0), 100)\n    def test_negative(self):\n        with self.assertRaises(ValueError):\n            total_with_tax(-1, .1)\n";
const SMOKE_BOOT=["python","-I","-S","-c","from pathlib import Path; Path('RIAN-Commander-Smoke').mkdir(exist_ok=True); print('RIAN_SMOKE_READY')"],SMOKE_RUN=["python","-I","-S","-m","unittest","discover","-s","RIAN-Commander-Smoke","-p","test_calculator.py","-v"];
const SMOKE_PIN="v1:fixed-safe-examples:2026-11-18";

const PROJECT_PROFILE="dev-workspace-edit-v1",PROJECT_CWD="Documents",PROJECT_DIR="Documents/RIAN-Commander-Smoke";
const PROJECT_FILE=PROJECT_DIR+"/calculator.py",PROJECT_NOTES=PROJECT_DIR+"/notes.md";
const PROJECT_COMPILE=["python","-I","-S","-m","py_compile","RIAN-Commander-Smoke/calculator.py"];
const PROJECT_PIN="v1:editor:only-two-files:read-hash:syntax-not-execution:2026-11-18",PROJECT_MAX_BYTES=5000,PROJECT_SNAPSHOT_TTL=900;
const projectSnapshots=new Map();
function projectDigest(value){return createHash("sha256").update(value,"utf8").digest("hex")}
function projectKey(client,path){return projectDigest(client+"|"+path)}
function projectTrackRead(client,path,content){
 if(typeof client!=="string"||!client.startsWith("rian.")||![PROJECT_FILE,PROJECT_NOTES].includes(path)||typeof content!=="string"||Buffer.byteLength(content,"utf8")>PROJECT_MAX_BYTES)return;
 if(projectSnapshots.size>=100)for(const [id,x] of projectSnapshots){if(x.until<=now())projectSnapshots.delete(id)}
 if(projectSnapshots.size>=100)projectSnapshots.delete(projectSnapshots.keys().next().value);
 projectSnapshots.set(projectKey(client,path),{hash:projectDigest(content),until:now()+PROJECT_SNAPSHOT_TTL});
}
export function projectWriteAllowed(a){
 if(!a||typeof a!=="object"||Array.isArray(a)||Object.keys(a).some(k=>!["path","content","overwrite"].includes(k)))return false;
 if(typeof a.content!=="string"||!a.content.trim()||a.content.includes("\0")||Buffer.byteLength(a.content,"utf8")>PROJECT_MAX_BYTES)return false;
 return a.path===PROJECT_FILE?a.overwrite===true:a.path===PROJECT_NOTES&&(a.overwrite===true||a.overwrite===false);
}
function projectDiff(a,b){
 const x=a.replace(/\r\n/g,"\n").split("\n"),y=b.replace(/\r\n/g,"\n").split("\n");
 let changed=0;for(let i=0;i<Math.max(x.length,y.length);i++)if(x[i]!==y[i])changed++;
 return {before_lines:x.length,after_lines:y.length,changed_lines_by_position:changed};
}
async function projectScopedWrite(sessionId,args,clientId){
 const grant=ownedSession(sessionId,clientId);
 if(grant.profile!==PROJECT_PROFILE||currentSessionState(grant)!=="ACTIVE"||grant.remaining<=0||!projectWriteAllowed(args))throw Error("Write denied outside approved scratch workspace");
 if(grant.busy)throw Error("Another scoped operation is running");
 grant.busy=true;
 try{
  if(grant.sourceHash!==await trustedSourceDigest(PROJECT_PROFILE)){grant.state="REVOKED";grant.remaining=0;throw Error("Editor policy changed; grant revoked")}
  let previous=null;
  if(args.overwrite){
   const snap=projectSnapshots.get(projectKey(clientId,args.path));
   if(!snap||snap.until<=now())throw Error("Read this source in chat before editing; snapshot missing or expired");
   const remote=await relay("rian_eemf_read_file",{path:args.path});
   previous=remote?.result?.content;
   if(typeof previous!=="string"||projectDigest(previous)!==snap.hash)throw Error("CAS conflict: file modified since last read; refresh first");
   if(previous===args.content)return sessionReply({device,profile:PROJECT_PROFILE,path:args.path,write_verified:true,no_change:true,remaining_calls:grant.remaining,sha256:snap.hash});
  }else if(args.path!==PROJECT_NOTES)throw Error("Only notes.md may be created without overwrite");
  if(currentSessionState(grant)!=="ACTIVE")throw Error("Grant expired before write");
  grant.remaining--;
  const label=args.path===PROJECT_FILE?"calculator.py":"notes.md";
  auditTrusted("workspace_patch_submitted",sessionId,{file:label,overwrite:args.overwrite,remaining:grant.remaining});
  await relay("rian_eemf_write_file",{path:args.path,content:args.content,overwrite:args.overwrite},true);
  const check=await relay("rian_eemf_read_file",{path:args.path});
  if(check?.result?.content!==args.content)throw Error("Write verification failed");
  projectTrackRead(clientId,args.path,args.content);
  const diff=projectDiff(previous||"",args.content);
  auditTrusted("workspace_patch_verified",sessionId,{file:label,changed_lines:diff.changed_lines_by_position,remaining:grant.remaining});
  return sessionReply({device,profile:PROJECT_PROFILE,state:currentSessionState(grant),path:args.path,write_verified:true,remaining_calls:grant.remaining,precondition_sha256:previous?projectDigest(previous):null,sha256:projectDigest(args.content),diff});
 }finally{grant.busy=false}
}

const DEV_PROFILE="dev-version-checks-v1",DEV_CWD="Documents";
const DEV_VERSION_CMDS=["python","git","node"];
const DEV_POLICY_PIN="rian-commander|dev-version-checks-v1|cwd=Documents|python --version|git --version|node --version|no-write|2026-11-18";
const DEV_APPROVAL_SECONDS=1800,DEFAULT_APPROVAL_SECONDS=300,DEV_APPROVAL_FORM_SECONDS=600;
function trustedWorkspace(profile){return profile===PROJECT_PROFILE?PROJECT_DIR:profile===SMOKE_PROFILE?SMOKE_DIR:profile===DEV_PROFILE?DEV_CWD:profile===OUTLOOK_PROFILE?OUTLOOK_CWD:TRUSTED_CWD;}
function trustedScript(profile){return profile===OUTLOOK_PROFILE?OUTLOOK_SOURCE:TRUSTED_SOURCE;}
const validSessionId=v=>typeof v==="string"&&/^[A-Za-z0-9_-]{32,64}$/.test(v);
export function ownedSession(id,clientId){
 if(!validSessionId(id)||!clientId)throw Error("Invalid session");
 const session=trustedSessions.get(id);
 if(!session||session.clientId!==clientId)throw Error("Unknown trusted session");
 return session;
}
function auditTrusted(event,id,extra={}){
 const sessionDigest=createHash("sha256").update(id).digest("hex").slice(0,14);
 console.info("RIAN_TRUSTED_AUDIT",JSON.stringify({event,session_digest:sessionDigest,at:now(),...extra}));
}
export function currentSessionState(session,at=now()){
 if(session.state==="PENDING_APPROVAL"&&session.requestUntil<=at)session.state="EXPIRED";
 if(session.state==="ACTIVE"&&(session.validUntil<=at||session.remaining<=0))session.state="EXPIRED";
 return session.state;
}
export function validateTrustedMailCommand(raw,profile=TRUSTED_PROFILE){
 if(profile===PROJECT_PROFILE){
  if(!raw||typeof raw!=="object"||Array.isArray(raw)||Object.keys(raw).some(k=>!["argv","cwd","timeout"].includes(k))||raw.cwd!==PROJECT_CWD)throw Error("Project compile scope denied");
  if(!Array.isArray(raw.argv)||raw.argv.length!==PROJECT_COMPILE.length||!PROJECT_COMPILE.every((part,i)=>raw.argv[i]===part))throw Error("Only exact py_compile syntax checking is allowed; no Python code execution");
  const timeout=raw.timeout===undefined?20:raw.timeout;
  if(!Number.isInteger(timeout)||timeout<1||timeout>35)throw Error("Compile timeout denied");
  return {argv:[...PROJECT_COMPILE],cwd:PROJECT_CWD,timeout};
 }

 if(profile===SMOKE_PROFILE){
  if(!raw||typeof raw!=="object"||Array.isArray(raw)||Object.keys(raw).some(k=>!["argv","cwd","timeout"].includes(k)))throw Error("Unapproved sandbox command fields");
  if(raw.cwd!==SMOKE_CWD||!Array.isArray(raw.argv))throw Error("Sandbox cwd denied");
  const exact=(one,two)=>one.length===two.length&&one.every((x,i)=>x===two[i]);
  if(!exact(raw.argv,SMOKE_BOOT)&&!exact(raw.argv,SMOKE_RUN))throw Error("Sandbox command not in exact allowlist");
  const timeout=raw.timeout===undefined?25:raw.timeout;
  if(!Number.isInteger(timeout)||timeout<1||timeout>35)throw Error("Sandbox timeout denied");
  return {argv:[...raw.argv],cwd:SMOKE_CWD,timeout};
 }

 if(profile===DEV_PROFILE){
  if(!raw||typeof raw!=="object"||Array.isArray(raw)||Object.keys(raw).some(k=>!["argv","cwd","timeout"].includes(k)))throw Error("Unapproved diagnostics fields");
  if(raw.cwd!==DEV_CWD)throw Error("Developer diagnostics locked to Documents");
  const argv=raw.argv;
  if(!Array.isArray(argv)||argv.length!==2||argv.some(v=>typeof v!=="string"||!v||v.length>80||/[\x00-\x1f\x7f]/.test(v)))throw Error("Invalid developer diagnostics argv");
  if(!DEV_VERSION_CMDS.includes(argv[0])||argv[1]!=="--version")throw Error("Only python/git/node --version may run under this trusted profile");
  const timeout=raw.timeout===undefined?15:raw.timeout;
  if(!Number.isInteger(timeout)||timeout<1||timeout>30)throw Error("Developer diagnostics timeout denied");
  return {argv:[...argv],cwd:DEV_CWD,timeout};
 }
 if(profile===OUTLOOK_PROFILE){
  if(!raw||typeof raw!=="object"||Array.isArray(raw)||Object.keys(raw).some(k=>!["argv","cwd","timeout"].includes(k)))throw Error("Unapproved Outlook fields");
  if(raw.cwd!==OUTLOOK_CWD)throw Error("Outlook workspace only");
  const argv=raw.argv;
  if(!Array.isArray(argv)||argv.length<3||argv.length>6||argv.some(x=>typeof x!=="string"||!x||x.length>120||/[\x00-\x1f\x7f]/.test(x)))throw Error("Invalid Outlook argv");
  if(argv[0]!=="python"||argv[1]!=="outlook_bridge.py")throw Error("Outlook command not in allowlist");
  if(argv[2]==="doctor"){if(argv.length!==3)throw Error("Unexpected doctor arguments");}
  else if(argv[2]==="search"){
   if(argv.length!==4&&argv.length!==6)throw Error("Invalid Outlook search");
   if(!argv[3].trim()||argv[3].startsWith("-"))throw Error("Invalid Outlook query");
   if(argv.length===6&&(argv[4]!=="--limit"||!/^\d{1,2}$/.test(argv[5])||Number(argv[5])<1||Number(argv[5])>20))throw Error("Outlook search limit denied");
  }else throw Error("Outlook profile permits only doctor and metadata search; no sync, read, or configure");
  const timeout=raw.timeout===undefined?30:raw.timeout;
  if(!Number.isInteger(timeout)||timeout<1||timeout>45)throw Error("Outlook timeout denied");
  return {argv:[...argv],cwd:OUTLOOK_CWD,timeout};
 }
 if(profile!==TRUSTED_PROFILE)throw Error("Unknown trust profile");
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
export function eligibleTrustProfile(operation,args){
 if(operation!=="rian_eemf_run_command")return null;
 for(const p of [PROJECT_PROFILE,SMOKE_PROFILE,DEV_PROFILE,OUTLOOK_PROFILE,TRUSTED_PROFILE]){try{validateTrustedMailCommand(args,p);return p}catch{}}
 return null;
}
export function approvalRequestSeconds(operation,args){
 return [PROJECT_PROFILE,SMOKE_PROFILE,DEV_PROFILE].includes(eligibleTrustProfile(operation,args))?DEV_APPROVAL_SECONDS:DEFAULT_APPROVAL_SECONDS;
}
async function trustedSourceDigest(profile=TRUSTED_PROFILE){
 if(profile===PROJECT_PROFILE)return projectDigest(PROJECT_PIN+PROJECT_DIR+PROJECT_FILE+PROJECT_NOTES+JSON.stringify(PROJECT_COMPILE));
 if(profile===SMOKE_PROFILE)return createHash("sha256").update(SMOKE_PIN+SMOKE_BUG+SMOKE_FIXED+SMOKE_TEST+JSON.stringify(SMOKE_BOOT)+JSON.stringify(SMOKE_RUN)).digest("hex");
 if(profile===DEV_PROFILE)return createHash("sha256").update(DEV_POLICY_PIN,"utf8").digest("hex");
 const fileResult=await relay("rian_eemf_read_file",{path:trustedScript(profile)});
 const content=fileResult?.result?.content;
 if(typeof content!=="string"||content.length<50||content.length>25000)throw Error("Trusted script unavailable");
 return createHash("sha256").update(content,"utf8").digest("hex");
}
function sessionSummary(id,session){
 return {session_id:id,device,profile:session.profile||TRUSTED_PROFILE,state:currentSessionState(session),expires_at:session.validUntil||null,remaining_calls:session.remaining,maximum_calls:TRUSTED_MAX_CALLS,workspace:trustedWorkspace(session.profile||TRUSTED_PROFILE)};
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
  if(Object.keys(args).some(k=>k!=="profile")||(args.profile!==undefined&&![TRUSTED_PROFILE,OUTLOOK_PROFILE,DEV_PROFILE,SMOKE_PROFILE,PROJECT_PROFILE].includes(args.profile)))throw Error("Unexpected trusted session parameters");
  return {profile:args.profile||TRUSTED_PROFILE};
 }
 if(name==="rian_eemf_trusted_session_status"||name==="rian_eemf_revoke_trusted_session"){
  if(Object.keys(args).length!==1||!validSessionId(args.session_id))throw Error("Invalid trusted session ID");
  return {session_id:args.session_id};
 }
 if(name==="rian_eemf_run_trusted_command"){
  if(Object.keys(args).some(k=>!["session_id","argv","cwd","timeout"].includes(k))||!validSessionId(args.session_id))throw Error("Invalid trusted request");
  const {session_id,...command}=args;
  return {session_id,...command};
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
  if(Object.keys(args).some(x=>!["argv","cwd","timeout","approval_mode"].includes(x)))throw Error("Unexpected args");
  if(!Array.isArray(args.argv)||args.argv.length<1||args.argv.length>20||args.argv.some(x=>typeof x!=="string"||!x.length||x.length>500||/[\x00-\x1f]/.test(x)))throw Error("Invalid argv");
  if(args.cwd!==undefined&&typeof args.cwd!=="string")throw Error("Invalid cwd");
  const cwd=args.cwd?safePath(args.cwd):undefined;
  const timeout=Number.isInteger(args.timeout)?args.timeout:30;
  if(timeout<1||timeout>90)throw Error("Timeout denied");
  const approval_mode=args.approval_mode===undefined?"choose":args.approval_mode;
  if(!["choose","each"].includes(approval_mode))throw Error("Unapproved approval mode");
  return {argv:args.argv,cwd,timeout,approval_mode};
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
export function newTrustedSession(clientId,profile=TRUSTED_PROFILE){
 if(![TRUSTED_PROFILE,OUTLOOK_PROFILE,DEV_PROFILE,SMOKE_PROFILE,PROJECT_PROFILE].includes(profile))throw Error("Unsupported trusted profile");
 if(typeof clientId!=="string"||!clientId.startsWith("rian."))throw Error("Authenticated client required");
 for(const [id,s] of trustedSessions){
  const state=currentSessionState(s);
  if(s.clientId===clientId&&(s.profile||TRUSTED_PROFILE)===profile&&(state==="PENDING_APPROVAL"||state==="VERIFYING"||state==="ACTIVE"))throw Error("Existing pending or active trusted session for this profile: "+id);
 }
 if(trustedSessions.size>=40){
  for(const [id,s] of trustedSessions){if(["EXPIRED","REVOKED"].includes(currentSessionState(s)))trustedSessions.delete(id)}
 }
 if(trustedSessions.size>=40)throw Error("Trusted session capacity reached");
 const id=rand(32);
 trustedSessions.set(id,{clientId,profile,state:"PENDING_APPROVAL",requestUntil:now()+TRUSTED_REQUEST_TTL,validUntil:null,remaining:0,sourceHash:null,busy:false,attempts:0});
 auditTrusted("requested",id,{profile});
 return sessionReply({session_id:id,state:"PENDING_APPROVAL",device,profile,approval_url:origin+"/session/approve/"+id,request_expires_in:TRUSTED_REQUEST_TTL,duration_after_approval_seconds:TRUSTED_DURATION_SECONDS,maximum_calls:TRUSTED_MAX_CALLS,selectable_duration_minutes:{minimum:1,maximum:60,default:30},warning:"Owner selects duration and approves with password in browser; no commands execute before approval."});
}
export function smokeWriteAllowed(a){
 if(!a||typeof a!=="object"||Object.keys(a).some(k=>!["path","content","overwrite"].includes(k)))return false;
 return (a.overwrite===false&&a.path===SMOKE_CALC&&a.content===SMOKE_BUG)
  ||(a.overwrite===false&&a.path===SMOKE_TEST_PATH&&a.content===SMOKE_TEST)
  ||(a.overwrite===true&&a.path===SMOKE_CALC&&a.content===SMOKE_FIXED);
}
async function smokeVerifySources(){
 const [calc,checks]=await Promise.all([relay("rian_eemf_read_file",{path:SMOKE_CALC}),relay("rian_eemf_read_file",{path:SMOKE_TEST_PATH})]);
 const norm=s=>typeof s==="string"?s.replace(/\r\n/g,"\n"):null;
 if(![SMOKE_BUG,SMOKE_FIXED].includes(norm(calc?.result?.content))||norm(checks?.result?.content)!==SMOKE_TEST)
  throw Error("Unknown sandbox source: refusing to execute Python tests");
}
async function smokeScopedWrite(id,args,clientId){
 const s=ownedSession(id,clientId);
 if(s.profile!==SMOKE_PROFILE||currentSessionState(s)!=="ACTIVE"||s.remaining<=0||!smokeWriteAllowed(args))throw Error("Write outside approved sandbox");
 if(s.busy)throw Error("Sandbox session busy");
 s.busy=true;
 try{
  if(s.sourceHash!==await trustedSourceDigest(SMOKE_PROFILE)){s.state="REVOKED";s.remaining=0;throw Error("Sandbox policy changed; approval revoked")}
  if(args.overwrite){
   const old=await relay("rian_eemf_read_file",{path:SMOKE_CALC});
   if(typeof old?.result?.content!=="string"||old.result.content.replace(/\r\n/g,"\n")!==SMOKE_BUG)throw Error("Overwrite refused: calculator.py differs from known buggy baseline");
  }
  if(currentSessionState(s)!=="ACTIVE")throw Error("Session expired");
  s.remaining--;auditTrusted("sandbox_write_submitted",id,{file:args.path===SMOKE_CALC?"calculator.py":"test_calculator.py",remaining:s.remaining,overwrite:args.overwrite});
  await relay("rian_eemf_write_file",args,true);
  const verified=await relay("rian_eemf_read_file",{path:args.path});
  if(typeof verified?.result?.content!=="string"||verified.result.content.replace(/\r\n/g,"\n")!==args.content)throw Error("File write verification mismatch");
  auditTrusted("sandbox_write_verified",id,{remaining:s.remaining});
  return sessionReply({device,profile:SMOKE_PROFILE,state:currentSessionState(s),path:args.path,write_verified:true,remaining_calls:s.remaining,sha256:createHash("sha256").update(args.content).digest("hex")});
 }finally{s.busy=false}
}
export async function trustedDispatch(name,args,clientId){
 if(name==="rian_eemf_request_trusted_session")return newTrustedSession(clientId,args.profile);
 const s=ownedSession(args.session_id,clientId),state=currentSessionState(s);
 if(name==="rian_eemf_trusted_session_status")return sessionReply(sessionSummary(args.session_id,s));
 if(name==="rian_eemf_revoke_trusted_session"){
  s.state="REVOKED";s.remaining=0;
  auditTrusted("revoked",args.session_id);
  return sessionReply(sessionSummary(args.session_id,s));
 }
 if(name!=="rian_eemf_run_trusted_command")throw Error("Unsupported session action");
 if(state!=="ACTIVE"||s.remaining<=0)throw Error("Trusted session inactive or expired; browser reapproval required");
 if(s.busy)throw Error("Trusted session busy; concurrent commands are not allowed");
 // Validate twice: tool arguments were previously checked; guard again at authorization.
 const {session_id, ...raw}=args;
 const safe=validateTrustedMailCommand(raw,s.profile||TRUSTED_PROFILE);
 s.busy=true;
 try{
  const digest=await trustedSourceDigest(s.profile||TRUSTED_PROFILE);
  if(s.sourceHash!==digest){s.state="REVOKED";s.remaining=0;throw Error("Trusted script changed; session revoked")};
  if(currentSessionState(s)!=="ACTIVE")throw Error("Trusted session no longer active");
  if(s.profile===SMOKE_PROFILE&&JSON.stringify(safe.argv)===JSON.stringify(SMOKE_RUN))await smokeVerifySources();
  // Consume a quota unit before submitting so failures cannot evade limits.
  s.remaining--;
  auditTrusted("command_submitted",session_id,{remaining:s.remaining});
  const out=await relay("rian_eemf_run_command",safe,true);
  auditTrusted("command_completed",session_id,{remaining:s.remaining});
  return sessionReply({session_id,device,profile:s.profile||TRUSTED_PROFILE,state:currentSessionState(s),remaining_calls:s.remaining,command:safe.argv,execution:out});
 }finally{s.busy=false}
}
async function sendBackend(name,args,clientId){
 if(name==="rian_eemf_request_trusted_session"||name==="rian_eemf_trusted_session_status"||name==="rian_eemf_run_trusted_command"||name==="rian_eemf_revoke_trusted_session")return trustedDispatch(name,args,clientId);
 if(name==="rian_eemf_status"||name==="rian_eemf_list_directory"||name==="rian_eemf_read_file"){
  const target=name;
  const val=await relay(target,args);
  if(name==="rian_eemf_read_file"&&typeof val?.result?.content==="string")projectTrackRead(clientId,args.path,val.result.content);
  if(JSON.stringify(val).length>100000)throw Error("Result too large");
  return {content:[{type:"text",text:JSON.stringify(val)}]};
 }
 if(name==="rian_eemf_action_status"){
  const a=actionQueue.get(args.action_id);
  if(!a||a.exp<now()||a.clientId!==clientId)throw Error("Unknown, expired or unauthorized action");
  return {content:[{type:"text",text:JSON.stringify({action_id:args.action_id,status:a.status,device,completed:a.done||null,summary:a.summary||null})}]};
 }
 if(name==="rian_eemf_request_write"){
  for(const [sid,s] of trustedSessions){
   if(s.clientId===clientId&&s.profile===SMOKE_PROFILE&&currentSessionState(s)==="ACTIVE"&&smokeWriteAllowed(args))
    return smokeScopedWrite(sid,args,clientId);
   if(s.clientId===clientId&&s.profile===PROJECT_PROFILE&&currentSessionState(s)==="ACTIVE"&&projectWriteAllowed(args))
    return projectScopedWrite(sid,args,clientId);
  }
 }
 if(name==="rian_eemf_request_command"){
  const {approval_mode,...command}=args;
  if(approval_mode!=="each"){
   const profile=eligibleTrustProfile("rian_eemf_run_command",command);
   if(profile)for(const [sid,s] of trustedSessions){
    if(s.clientId===clientId&&(s.profile||TRUSTED_PROFILE)===profile&&currentSessionState(s)==="ACTIVE")
     return trustedDispatch("rian_eemf_run_trusted_command",{session_id:sid,...command},clientId);
   }
  }
  args=command;
 }
 const actionId=rand(32);
 if(actionQueue.size>80){for(const [id,x] of actionQueue){if(x.exp<now()||x.status==="COMPLETE")actionQueue.delete(id)}}
 if(actionQueue.size>80)throw Error("Action queue full");
 const operation=name==="rian_eemf_request_command"?"rian_eemf_run_command":"rian_eemf_write_file";
 const ttl=approvalRequestSeconds(operation,args),issuedAt=now();
 actionQueue.set(actionId,{operation,args,clientId,status:"PENDING_APPROVAL",issuedAt,exp:issuedAt+ttl});
 return {content:[{type:"text",text:JSON.stringify({action_id:actionId,device,status:"PENDING_APPROVAL",preview:operation==="rian_eemf_run_command"?{argv:args.argv,cwd:args.cwd||null,timeout:args.timeout}:{path:args.path,overwrite:args.overwrite,contentLength:args.content.length},approval_url:origin+"/approve/"+actionId,expires_in_seconds:ttl,expires_at:issuedAt+ttl,note:ttl===DEV_APPROVAL_SECONDS?"No action executed. Safe version check approval valid 30 minutes. Browser owner approves once or selects a scoped session.":"No action executed. General command or write approval expires in 5 minutes and requires separate owner confirmation."})}]};
}

const ownerPortalSessions=new Map();
const OWNER_PORTAL_COOKIE="__Host-rian_owner_portal";
function portalCookie(req,key){
 const value=(req.headers.get("cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(key+"="));
 return value?value.slice(key.length+1):"";
}
function portalForm(req,max=72000){return req.text().then(x=>{if(x.length>max)throw Error("Form too large");return new URLSearchParams(x)})}
function portalCSRF(s){return ticket({type:"rian-owner-form",sid:s.sid,exp:Math.min(s.exp,now()+600),nonce:rand(12)})}
function portalSession(req){
 const data=unticket(portalCookie(req,OWNER_PORTAL_COOKIE));
 if(!data||data.type!=="rian-owner-session"||typeof data.sid!=="string")return null;
 const active=ownerPortalSessions.get(data.sid);
 if(!active||active.exp!==data.exp||active.exp<=now()){if(active)ownerPortalSessions.delete(data.sid);return null}
 return {sid:data.sid,exp:data.exp,clientId:"rian.browser."+data.sid};
}
function portalValid(req,form,s){
 const provided=req.headers.get("origin")||"";
 if(provided!==""&&provided!=="null"&&provided!==origin)return false;
 const raw=form.get("csrf")||"",val=raw.length<600?unticket(raw):null;
 return !!val&&val.type==="rian-owner-form"&&val.sid===s.sid;
}

const PORTAL_CSS=String.raw`
*{box-sizing:border-box}html{color-scheme:dark}body{margin:0;color:#e7f0fd;font:14px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;background:#0b1423}a{color:#a8cafd;text-decoration:none}h1{font-size:32px;letter-spacing:-.045em;line-height:1.2;margin:5px 0 10px}h2{font-size:18px;margin:0 0 7px}h3{font-size:14px;margin:0}p{color:#a7bcd7;margin:6px 0 15px}.shell{display:grid;grid-template-columns:215px minmax(0,1fr);min-height:100vh;max-width:1330px;margin:auto}.side{padding:26px 16px;background:#101c2e;border-right:1px solid #304360}.brand{font-size:19px;font-weight:850;letter-spacing:.04em;color:#fff}.brand span{color:#84b7ff}.nav{display:grid;gap:7px;margin-top:35px}.nav a{padding:12px;border-radius:9px;color:#a8bbd4}.nav a:hover,.nav a.selected{background:#213857;color:#fff}.side-note{margin-top:30px;border:1px solid #34506d;background:#12263f;border-radius:11px;padding:15px;color:#bad0e8;font-size:12px}.main{padding:35px clamp(16px,4vw,48px) 60px;min-width:0}.eyebrow{font-size:11px;letter-spacing:.14em;color:#8bb8fc;font-weight:750}.headline{display:flex;justify-content:space-between;align-items:flex-start;gap:15px;flex-wrap:wrap}.chip{font-size:12px;border-radius:20px;background:#183253;color:#bad6fa;border:1px solid #3c5d80;padding:6px 11px;white-space:nowrap}.tiles{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:13px;margin:23px 0}.tile,.panel{border:1px solid #304764;border-radius:14px;background:#14243a;padding:20px}.tile small{display:block;color:#9bb5d1;font-size:12px}.tile b{display:block;font-size:17px;margin-top:7px}.tile p{font-size:12px;margin:0}.panel{margin:15px 0}.panel-heading{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}.fields{display:grid;gap:13px}.field label{display:block;font-size:12px;font-weight:750;color:#c0d1e6;margin-bottom:6px}.field input,.field textarea,.field select{width:100%;border-radius:9px;border:1px solid #48617f;background:#0e1d32;color:#f3f8ff;padding:12px;font:14px system-ui;outline-offset:3px}.field textarea{min-height:115px;resize:vertical;font-family:ui-monospace,Consolas,monospace}.field input:focus,.field textarea:focus,.field select:focus{outline:2px solid #78aefe}.mono,code,pre{font-family:ui-monospace,Consolas,monospace}button,.button{font:inherit;font-weight:750;cursor:pointer;border:0;border-radius:9px;background:#4c8afa;color:#fff;padding:12px 17px;display:inline-block;text-align:center}button:hover,.button:hover{background:#71a3ff;color:#fff}.secondary{background:#253e5c;border:1px solid #45617e}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.between{justify-content:space-between}.muted{color:#94aecb}.notice{border-left:3px solid #72aafb;background:#10253f;border-radius:6px;padding:12px 15px;margin:14px 0;color:#cedff6}.warning{border-left-color:#edc079;background:#30291e}.links{display:flex;flex-wrap:wrap;gap:10px}.links a{padding:10px 12px;border:1px solid #425f82;border-radius:9px}details{margin-top:14px;border:1px solid #34506f;border-radius:10px;padding:15px;background:#101e32}summary{cursor:pointer;font-weight:750;color:#d7e5f6}summary:hover{color:#fff}.checkbox{display:flex;align-items:flex-start;gap:9px;color:#e8cfa7}.checkbox input{width:16px;margin-top:4px}pre{background:#0c192c;padding:13px;border-radius:9px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere}.history{display:flex;justify-content:space-between;gap:8px;border-top:1px solid #304762;padding:8px 0}.status{color:#a7d4ff}footer{font-size:12px;color:#809bb9;margin-top:30px}@media(max-width:840px){.shell{grid-template-columns:1fr}.side{padding:15px;border-right:0;border-bottom:1px solid #304360}.nav{display:flex;gap:6px;margin-top:12px;overflow:auto}.nav a{white-space:nowrap}.side-note{display:none}.main{padding:22px 16px}.tiles{grid-template-columns:1fr}}
`;
function portalShell(content,status=200){
 const nav='<aside class="side"><div class="brand">RIAN <span>COMMANDER</span></div><nav class="nav"><a class="selected" href="/operator">원격 작업</a><a href="https://rian-commander-oauth-gateway-production.up.railway.app/console">파일 탐색</a><a href="https://rian-commander-oauth-gateway-production.up.railway.app/verify">기능 검증</a></nav><div class="side-note"><strong>DESKTOP-EEMFO3L</strong><p>원격 명령과 파일 쓰기는 별도의 소유자 승인이 있어야 실행됩니다.</p></div></aside>';
 const page='<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="same-origin"><title>RIAN Commander | 원격 작업</title><style>'+PORTAL_CSS+'</style></head><body><div class="shell">'+nav+'<main class="main">'+content+'<footer>RIAN Commander · EEMFO3L 전용 · 명령과 파일 변경은 별도 소유자 승인</footer></main></div></body></html>';
 return new Response(page,{status,headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store","referrer-policy":"same-origin","x-content-type-options":"nosniff","content-security-policy":"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"}});
}
function portalLogin(msg="",status=200){
 const csrf=ticket({type:"rian-owner-login",exp:now()+600,nonce:rand(12)});
 const notice=msg?'<div class="notice warning">'+escape(msg)+'</div>':"";
 const content='<div class="eyebrow">OWNER ACCESS</div><h1>원격 개발 관리</h1><p>PC의 파일을 관리하고 터미널 명령을 승인할 수 있는 소유자 전용 화면입니다.</p>'+
 '<div class="tiles"><div class="tile"><small>대상 PC</small><b>EEMFO3L</b><p>등록된 Windows PC</p></div><div class="tile"><small>실행 방식</small><b>승인 필수</b><p>로그인만으로 작업하지 않음</p></div><div class="tile"><small>유지시간</small><b>1–60분</b><p>사용자 직접 선택</p></div></div>'+notice+
 '<section class="panel"><h2>소유자 로그인</h2><p>로그인은 관리 화면 접근용입니다. 명령 실행·파일 변경은 별도로 승인해야 합니다.</p>'+
 '<form method="POST" action="/operator/login" class="fields"><input type="hidden" name="csrf" value="'+escape(csrf)+'">'+
 '<div class="field"><label for="portal-password">RIAN Commander 소유자 암호</label><input id="portal-password" type="password" name="password" minlength="20" maxlength="299" required autocomplete="current-password"></div>'+
 '<div class="field"><label for="portal-minutes">화면 로그인 유지시간 (분)</label><input id="portal-minutes" name="minutes" type="number" min="1" max="60" step="1" value="30" required></div>'+
 '<button type="submit">관리 화면 열기</button></form></section>'+
 '<section class="panel"><h2>파일을 조회하려면</h2><p>다른 PC까지 파일을 탐색하고 미리보려면 읽기 전용 관리 콘솔을 사용하세요.</p><div class="links"><a href="https://rian-commander-oauth-gateway-production.up.railway.app/console">파일 관리 콘솔 열기</a></div></section>';
 const response=portalShell(content,status);
 response.headers.append("Set-Cookie","__Host-rian_owner_login="+csrf+"; Path=/; Max-Age=600; Secure; HttpOnly; SameSite=Strict");
 return response;
}
function portalPage(s,msg="",status=200){
 const csrf=portalCSRF(s),notice=msg?'<section class="panel"><h2>작업 요청 결과</h2>'+msg+'</section>':"";
 const expire=escape(new Date(s.exp*1000).toLocaleString("ko-KR",{timeZone:"Asia/Seoul"}));
 const actions=[...actionQueue.entries()].filter(([,a])=>a.clientId===s.clientId).slice(-5).reverse();
 const recent=actions.length?actions.map(([id,a])=>'<div class="history"><span><code>'+escape(id.slice(0,12))+'…</code> '+escape(a.operation==="rian_eemf_write_file"?"파일 변경":"명령 실행")+' · <span class="status">'+escape(a.status||"UNKNOWN")+'</span></span><form method="POST" action="/operator/status"><input type="hidden" name="csrf" value="'+escape(csrf)+'"><input type="hidden" name="action_id" value="'+escape(id)+'"><button type="submit" class="secondary">결과 확인</button></form></div>').join(""):'<p>이 로그인 세션에서 요청한 작업이 없습니다.</p>';
 const header='<div class="headline"><div><div class="eyebrow">EEMFO3L / OWNER WORKSPACE</div><h1>원격 작업</h1><p>파일 확인, 명령 승인, 작업 결과 확인을 한 곳에서 관리합니다.</p></div><span class="chip">소유자 로그인됨</span></div>'+
 '<div class="tiles"><div class="tile"><small>대상 PC</small><b>DESKTOP-EEMFO3L</b><p>다른 PC 제어 권한 없음</p></div><div class="tile"><small>명령·파일 변경</small><b>승인 요청만</b><p>별도 암호 승인 후 실행</p></div><div class="tile"><small>로그인 만료</small><b style="font-size:15px">'+expire+'</b><p>만료 시 자동 종료</p></div></div>';
 const files='<section class="panel"><div class="panel-heading"><div><h2>파일 탐색</h2><p>등록 PC의 파일·폴더 조회, 검색 및 코드 미리보기</p></div><span class="chip">읽기 전용</span></div><div class="links"><a href="https://rian-commander-oauth-gateway-production.up.railway.app/console">파일 관리 콘솔 열기</a><a href="https://rian-commander-oauth-gateway-production.up.railway.app/verify">실기기 검증</a></div></section>';
 const terminal='<section class="panel"><div class="panel-heading"><div><h2>원격 터미널</h2><p>기본 명령을 선택하면 복잡한 JSON 입력 없이 요청할 수 있습니다.</p></div><span class="chip">별도 승인</span></div>'+
 '<form method="POST" action="/operator/draft" class="fields"><input type="hidden" name="csrf" value="'+escape(csrf)+'"><input type="hidden" name="kind" value="command"><input type="hidden" name="cwd" value="Documents"><input type="hidden" name="timeout" value="30">'+
 '<div class="field"><label for="cmd-preset">확인 명령 선택</label><select name="preset" id="cmd-preset"><option value="python-version">Python 버전 확인</option><option value="git-version">Git 버전 확인</option><option value="node-version">Node.js 버전 확인</option></select></div>'+
 '<p class="muted">대상 PC: EEMFO3L / 실행 폴더: Documents / 최대 30초</p>'+
 '<button type="submit">선택한 명령 승인 요청 만들기</button></form>'+
 '<details><summary>고급 명령 직접 입력</summary><p>명령과 인자를 JSON 배열로 입력합니다. 실제 실행 전 승인 화면에서 다시 확인합니다.</p>'+
 '<form method="POST" action="/operator/draft" class="fields"><input type="hidden" name="csrf" value="'+escape(csrf)+'"><input type="hidden" name="kind" value="command">'+
 '<div class="field"><label for="cwd">작업 폴더</label><input id="cwd" name="cwd" value="Documents" required maxlength="350"></div>'+
 '<div class="field"><label for="argv">명령 인자(JSON)</label><textarea id="argv" name="argv" rows="4" maxlength="2500" required>["python","--version"]</textarea></div>'+
 '<div class="field"><label for="timeout">제한시간 (초)</label><input name="timeout" id="timeout" type="number" min="1" max="90" value="30" required></div><button type="submit" class="secondary">고급 명령 승인 요청</button></form></details></section>';
 const writing='<section class="panel"><div class="panel-heading"><div><h2>파일 생성·수정</h2><p>먼저 파일 내용을 확인하고, 변경은 승인 요청으로 진행합니다.</p></div><span class="chip">변경 승인</span></div>'+
 '<details><summary>파일 쓰기 요청 작성</summary><div class="notice warning">덮어쓰기는 기존 파일 전체 내용을 교체할 수 있습니다. 중요한 파일은 사전에 백업하세요.</div>'+
 '<form method="POST" action="/operator/draft" class="fields"><input type="hidden" name="csrf" value="'+escape(csrf)+'"><input type="hidden" name="kind" value="write">'+
 '<div class="field"><label for="write-path">파일 경로 (Documents 아래)</label><input name="path" id="write-path" required maxlength="350" placeholder="Documents/rian-commander-tests/notes.md"></div>'+
 '<div class="field"><label for="write-content">파일 내용 (최대 8,000자)</label><textarea name="content" id="write-content" rows="7" maxlength="8000" required placeholder="저장할 텍스트 내용을 입력하세요."></textarea></div>'+
 '<label class="checkbox"><input type="checkbox" name="overwrite" value="true">기존 파일을 전체 내용으로 덮어씁니다 (최종 별도 승인)</label>'+
 '<button type="submit">파일 변경 승인 요청 생성</button></form></details></section>';
 const requests='<section class="panel"><h2>승인 요청 · 작업 결과</h2><p>작업 요청을 생성하면 별도 승인 화면에서 허가한 뒤 상태를 조회할 수 있습니다.</p>'+recent+
 '<form method="POST" action="/operator/status" class="fields"><input type="hidden" name="csrf" value="'+escape(csrf)+'">'+
 '<div class="field"><label for="action-id">작업 ID</label><input name="action_id" id="action-id" required maxlength="64" placeholder="승인 요청 후 발급된 작업 ID"></div>'+
 '<button class="secondary" type="submit">작업 상태 확인</button></form></section>';
 const logout='<section class="panel"><div class="row between"><div><h3>세션 종료</h3><p>현재 원격 작업 화면에서 로그아웃합니다.</p></div><form method="POST" action="/operator/logout"><input type="hidden" name="csrf" value="'+escape(csrf)+'"><button class="secondary">로그아웃</button></form></div></section>';
 const note='<div class="notice">이 페이지는 <strong>승인 요청을 작성하는 화면</strong>입니다. 소유자 암호로 별도 승인하기 전에는 파일을 수정하거나 명령을 실행하지 않습니다.</div>';
 return portalShell(header+note+notice+files+terminal+writing+requests+logout,status);
}

async function portalHandle(req,p,m){
 if(p==="/operator"&&m==="GET"){const s=portalSession(req);return s?portalPage(s):portalLogin()}
 if(p==="/operator/login"&&m==="POST"){
  const orig=req.headers.get("origin")||"";
  if(orig!==""&&orig!=="null"&&orig!==origin)return portalLogin("외부 출처 요청 차단",403);
  let f;try{f=await portalForm(req,1300)}catch{return portalLogin("입력 오류",400)}
  if([...f.keys()].some(x=>!["csrf","password","minutes"].includes(x)))return portalLogin("허용되지 않는 필드",400);
  const csrf=f.get("csrf")||"",t=csrf.length<600?unticket(csrf):null;
  if(!t||t.type!=="rian-owner-login"||portalCookie(req,"__Host-rian_owner_login")!==csrf)return portalLogin("보안 검증 실패",403);
  const minutes=f.get("minutes")||"";
  if(!/^(?:[1-9]|[1-5]\d|60)$/.test(minutes))return portalLogin("유효시간 오류",400);
  const key="owner-portal:"+((req.headers.get("cf-connecting-ip")||req.headers.get("x-forwarded-for")||"unknown").split(",")[0]).slice(0,60);
  let fail=loginFailures.get(key)||{count:0,until:now()+900};
  if(fail.until<=now())fail={count:0,until:now()+900};
  if(fail.count>=6)return portalLogin("로그인 시도 초과",429);
  if(!passwordOK(f.get("password")||"")){fail.count++;loginFailures.set(key,fail);return portalLogin("암호 오류",401)}
  loginFailures.delete(key);
  if(ownerPortalSessions.size>=20)for(const [id,x] of ownerPortalSessions){if(x.exp<=now())ownerPortalSessions.delete(id)}
  if(ownerPortalSessions.size>=20)return portalLogin("활성 세션 제한",429);
  const sid=rand(18),exp=now()+Number(minutes)*60;
  ownerPortalSessions.set(sid,{exp});
  const out=portalPage({sid,exp,clientId:"rian.browser."+sid});
  out.headers.append("Set-Cookie",OWNER_PORTAL_COOKIE+"="+ticket({type:"rian-owner-session",sid,exp})+"; Path=/; Max-Age="+Number(minutes)*60+"; Secure; HttpOnly; SameSite=Strict");
  out.headers.append("Set-Cookie","__Host-rian_owner_login=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict");
  return out;
 }
 const s=portalSession(req);
 if(!s)return portalLogin("로그인이 만료되었습니다.",401);
 let f;try{f=await portalForm(req)}catch{return portalPage(s,"입력 오류",400)}
 if(!portalValid(req,f,s))return portalPage(s,"보안 검증 실패",403);
 if(p==="/operator/logout"&&m==="POST"){
  ownerPortalSessions.delete(s.sid);
  const out=portalLogin("로그아웃 완료");
  out.headers.append("Set-Cookie",OWNER_PORTAL_COOKIE+"=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict");
  return out;
 }
 if(p==="/operator/status"&&m==="POST"){
  const id=f.get("action_id")||"",a=/^[A-Za-z0-9_-]{32,64}$/.test(id)?actionQueue.get(id):null;
  if(!a||a.clientId!==s.clientId)return portalPage(s,"이 로그인 세션의 작업이 아닙니다.",404);
  let safeOutput="";
  if(a.status==="COMPLETE"&&a.operation==="rian_eemf_run_command"&&Array.isArray(a.args?.argv)&&a.args.argv.length===2&&["python","git","node"].includes(a.args.argv[0])&&a.args.argv[1]==="--version"){
   try{
    const result=JSON.parse(a.summary||"{}");
    const data=result.result||result.execution?.result||{};
    const output=String(data.stdout||data.stderr||"").slice(0,350);
    if(output&&!/(?:secret|password|bearer|token|credential|authorization|private.?key)/i.test(output))
     safeOutput='<p>실행 결과</p><pre>'+escape(output)+'</pre>';
   }catch{}
  }
  const details='<h2>작업 결과</h2><p>상태: <strong>'+escape(a.status||"UNKNOWN")+'</strong></p>'+
   '<p>작업 유형: '+escape(a.operation==="rian_eemf_write_file"?"파일 생성·수정":"원격 명령")+'</p>'+
   '<p>작업 ID: <code>'+escape(id)+'</code></p>'+
   '<p>완료 시각: '+escape(a.done?new Date(a.done*1000).toLocaleString("ko-KR",{timeZone:"Asia/Seoul"}):"아직 미완료")+'</p>'+safeOutput+
   '<p class="muted">버전 확인 명령 외의 출력은 화면에 표시하지 않습니다.</p>';
  return portalPage(s,details);
 }
 if(p==="/operator/draft"&&m==="POST"){
  const kind=f.get("kind");let name,args;
  try{
   if(kind==="write"){
    if([...f.keys()].some(k=>!["csrf","kind","path","content","overwrite"].includes(k)))throw Error("필드 오류");
    const path=f.get("path")||"",content=f.get("content")||"";
    const clean=safePath(path);
    if(!clean.startsWith("Documents/")||clean.split("/").some(x=>/^(?:private|secrets?|credentials?|tokens?|backup|outbox|onedrive)$/i.test(x))||!/\.(?:md|txt|ts|tsx|js|jsx|py|java|go|rs|css|html|yml|yaml)$/i.test(clean)||!content||content.length>8000)throw Error("Documents 내 허용 텍스트 파일만 가능합니다");
    name="rian_eemf_request_write";
    args=safeArgs(name,{path:clean,content,overwrite:f.get("overwrite")==="true"});
   }else if(kind==="command"){
    if([...f.keys()].some(k=>!["csrf","kind","cwd","argv","timeout","preset"].includes(k)))throw Error("필드 오류");
    const cwd=f.get("cwd")||"";
    if(cwd!=="Documents"&&(!safePath(cwd).startsWith("Documents/")||safePath(cwd).split("/").some(x=>/^(?:private|secrets?|credentials?|tokens?|backup|outbox|onedrive)$/i.test(x))))throw Error("Documents 내 안전한 작업 폴더만 허용");
    const preset=f.get("preset")||"";
    const presetMap={"python-version":["python","--version"],"git-version":["git","--version"],"node-version":["node","--version"]};
    if(preset&&!Object.hasOwn(presetMap,preset))throw Error("선택한 기본 명령이 허용되지 않습니다.");
    if(preset&&f.has("argv"))throw Error("기본 명령과 고급 명령을 동시에 입력할 수 없습니다.");
    const argv=preset?[...presetMap[preset]]:JSON.parse(f.get("argv")||"[]");
    const timeout=f.get("timeout")||"";
    if(!/^(?:[1-9]|[1-8]\d|90)$/.test(timeout))throw Error("제한시간 오류");
    name="rian_eemf_request_command";
    args=safeArgs(name,{argv,cwd,timeout:Number(timeout),approval_mode:"each"});
   }else throw Error("작업 종류 오류");
   const response=await sendBackend(name,args,s.clientId);
   const item=JSON.parse(response?.content?.[0]?.text||"{}");
   if(item.status!=="PENDING_APPROVAL"||!item.action_id||item.approval_url!==origin+"/approve/"+item.action_id)throw Error("승인 요청 생성 실패");
   const detail='<h2>작업 실행 대기</h2><p>아직 실행되지 않았습니다. 검토 후 별도 승인하세요.</p><p>작업 ID: <code>'+escape(item.action_id)+'</code></p>'+
    '<p><a class="button" href="/approve/'+escape(item.action_id)+'">작업 내용을 확인하고 승인하기</a></p>';
   console.info("RIAN_OPERATOR_AUDIT",JSON.stringify({kind,device,at:now(),event:"draft_created",action_digest:createHash("sha256").update(item.action_id).digest("hex").slice(0,12)}));
   return portalPage(s,detail);
  }catch(e){return portalPage(s,"승인 요청이 생성되지 않았습니다: "+escape(String(e.message).slice(0,160)),400)}
 }
 return portalPage(s,"알 수 없는 경로",404);
}

function loginPage(ticketData,msg=""){return html('<h1>RIAN Commander — EEMFO3L 운영 연결</h1><p>이 서버는 EEMFO3L 파일 조회를 제공하고, 명령 실행과 파일 수정은 건별로 별도 브라우저 승인을 요구합니다. 다른 PC 실행 권한은 제공하지 않습니다.</p>'+(msg?'<p role="alert">'+escape(msg)+'</p>':"")+'<form method="POST" action="/oauth/approve"><input type="hidden" name="request" value="'+escape(ticketData)+'"><label for="password">소유자 암호</label><input name="password" id="password" type="password" minlength="20" autocomplete="current-password" required><button type="submit">EEMF 운영 연결 승인</button></form>')}
function passwordOK(provided){
 if(typeof provided!=="string"||provided.length<20||provided.length>=300)return false;
 const hash=scryptSync(provided,createHash("sha256").update("rian-commander-owner-password-v1:"+secret).digest().subarray(0,16),32);
 return timingSafeEqual(hash,pwHash);
}
function actionPage(id,item,msg=""){
 const description=item.operation==="rian_eemf_run_command"?JSON.stringify({argv:item.args.argv,cwd:item.args.cwd||null,timeout:item.args.timeout},null,2):JSON.stringify({path:item.args.path,overwrite:item.args.overwrite,content:item.args.content},null,2);
 const profile=item.clientId?eligibleTrustProfile(item.operation,item.args):null;
 const proof=ticket({type:"eemf-action-approval",id,exp:now()+([PROJECT_PROFILE,SMOKE_PROFILE,DEV_PROFILE].includes(profile)?DEV_APPROVAL_FORM_SECONDS:240),nonce:rand(16)});
 const label=profile===PROJECT_PROFILE?"격리 테스트 프로젝트 calculator.py·notes.md 파일 수정(원본 해시 검증)과 Python 문법 검사만":profile===SMOKE_PROFILE?"격리 테스트 폴더의 지정된 Python 파일 2개 생성·단일 오류 수정·고정 테스트 실행":profile===DEV_PROFILE?"개발 환경 버전 확인 (Python · Git · Node.js, Documents 폴더만)":profile===OUTLOOK_PROFILE?"Outlook 로컬 메일 메타데이터 검색":profile===TRUSTED_PROFILE?"Proton 로컬 색인 상태·제목 검색":"";
 const options=profile?
  '<label for="approval_mode">승인 방식</label><select id="approval_mode" name="approval_mode"><option value="once" selected>이번 명령만 승인</option><option value="timed">선택한 시간 동안 같은 범위 반복 허용</option></select>'+
  '<p>허용 범위: '+escape(label)+'. '+escape(profile===PROJECT_PROFILE?"승인하면 전용 폴더의 calculator.py와 notes.md를 채팅에서 수정할 수 있습니다. 반드시 먼저 파일을 읽고 해시가 일치해야 합니다. 코드를 실행하는 테스트는 허용되지 않으며 Python 문법 검사만 가능합니다. 다른 파일 및 삭제는 불가합니다.":profile===SMOKE_PROFILE?"승인하면 고정된 테스트 코드의 파일 생성·수정과 테스트 실행이 추가 암호 없이 가능합니다. 다른 폴더·명령·삭제는 허용되지 않습니다.":"해당 범위 외 명령, 파일 변경·삭제, 메일 본문 조회·동기화는 포함되지 않습니다.")+'</p>'+
  '<label for="duration_minutes">시간 제한 세션 유효시간 (분, 1~60)</label><input id="duration_minutes" name="duration_minutes" type="number" min="1" max="60" step="1" value="30" required>'+
  '<p>시간 제한 방식에서만 적용됩니다. 최대 60회 실행하면 시간과 관계없이 만료됩니다.</p>':
  '<input type="hidden" name="approval_mode" value="once"><p>이 명령은 반복 허용 대상이 아니므로 이번 1회만 승인할 수 있습니다.</p>';
 return html('<h1>EEMFO3L 작업 승인</h1><p>대상 PC: DESKTOP-EEMFO3L</p><p>승인 요청 만료 시각: '+escape(new Date(item.exp*1000).toLocaleString("ko-KR",{timeZone:"Asia/Seoul"}))+' (한국시간). 이 버전 확인 요청은 최대 30분, 일반 명령·파일 쓰기는 5분입니다.</p><p>사용자가 승인 방식과 시간을 선택합니다.</p><pre style="white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1423;padding:12px">'+escape(description)+'</pre>'+(msg?'<p role="alert">'+escape(msg)+'</p>':"")+'<form method="POST" action="/action/approve"><input type="hidden" name="request" value="'+escape(proof)+'">'+options+'<label for="password">소유자 암호</label><input name="password" id="password" type="password" minlength="20" autocomplete="current-password" required><button type="submit">선택한 방식으로 승인 및 실행</button></form>',200,"same-origin");
}
function trustedSessionPage(id,s){
 const nonce=ticket({type:"eemf-trusted-session-approval",id,exp:now()+240,nonce:rand(16)});
 return html('<h1>EEMFO3L 읽기 전용 세션 승인</h1>'+
 '<p>대상 장치: DESKTOP-EEMFO3L</p><p>프로필: '+escape(s.profile===OUTLOOK_PROFILE?'Outlook 로컬 메일 메타데이터 검색':'Proton 로컬 메일 색인 상태와 제목 검색')+'</p>'+
 '<p>허용: '+escape(s.profile===DEV_PROFILE?'python --version / git --version / node --version (Documents 폴더만)':s.profile===OUTLOOK_PROFILE?'python outlook_bridge.py doctor / search TERM --limit 1..20':'python proton_mail_query.py status / search TERM --limit 1..20')+'</p>'+
 '<p>허용하지 않음: 메일 본문 조회 명령, 메일 발송, IMAP 동기화, 임의 파일 변경, PowerShell, 임의 스크립트, 다른 PC 제어. Outlook 검색 결과 JSON만 로컬 갱신합니다.</p>'+
 '<label for="duration_minutes">세션 시간 (분, 1~60)</label><input id="duration_minutes" type="number" name="duration_minutes" min="1" max="60" step="1" value="30" required><p>설정한 시간 또는 최대 60회 실행 중 먼저 도달하면 자동 만료됩니다.</p>'+
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
 if(p==="/operator"||p.startsWith("/operator/"))return portalHandle(req,p,m);
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
  const durationMinutes=validDurationMinutes(values.get("duration_minutes")||"");
  if(durationMinutes===null)return html("<h1>세션 시간 오류</h1><p>1~60분을 선택하세요.</p>",400);
  // Race-safe state switch: multiple overlapping approval POSTs cannot activate twice.
  s.state="VERIFYING";
  try{
   const sourceHash=await trustedSourceDigest(s.profile||TRUSTED_PROFILE);
   if(s.state!=="VERIFYING"||s.requestUntil<=now())throw Error("Approval expired or revoked");
   s.sourceHash=sourceHash;
   s.state="ACTIVE";s.validUntil=now()+durationMinutes*60;s.remaining=TRUSTED_MAX_CALLS;
   auditTrusted("activated",proof.id,{expires_at:s.validUntil,max_calls:TRUSTED_MAX_CALLS,duration_minutes:durationMinutes});
   return html("<h1>제한형 세션 승인 완료</h1><p>DESKTOP-EEMFO3L "+escape(s.profile===PROJECT_PROFILE?"격리 프로젝트 코드 수정 및 문법 검사":s.profile===DEV_PROFILE?"개발 환경 버전 확인":s.profile===OUTLOOK_PROFILE?"Outlook 메타데이터 검색":"Proton 색인 상태·제목 검색")+"을 "+durationMinutes+"분간 최대 60회 허용했습니다. 허용되지 않은 모든 명령은 기존대로 별도 승인이 필요합니다.</p>");
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
  const mode=f.get("approval_mode")||"once";
  if(mode!=="once"&&mode!=="timed")return html("<h1>유효하지 않은 승인 방식</h1>",400);
  const profile=eligibleTrustProfile(item.operation,item.args);
  const durationMinutes=mode==="timed"?validDurationMinutes(f.get("duration_minutes")||""):null;
  if(mode==="timed"&&(durationMinutes===null||!profile||!item.clientId))return html("<h1>허용되지 않은 시간 제한 승인</h1>",400);
  if(mode==="timed")for(const s of trustedSessions.values()){
   if(s.clientId===item.clientId&&(s.profile||TRUSTED_PROFILE)===profile&&["PENDING_APPROVAL","VERIFYING","ACTIVE"].includes(currentSessionState(s)))
    return html("<h1>이미 활성화된 동일 범위 세션이 있습니다.</h1>",409);
  }
  const ip=(req.headers.get("cf-connecting-ip")||req.headers.get("x-forwarded-for")||"global").split(",")[0].slice(0,60),key="eemf-approval:"+ip;
  let failure=loginFailures.get(key)||{count:0,until:now()+600};if(failure.until<now())failure={count:0,until:now()+600};
  if(failure.count>=6)return html("<h1>암호 시도 횟수 초과</h1>",429);
  if(!passwordOK(f.get("password")||"")){failure.count++;loginFailures.set(key,failure);return html("<h1>암호 불일치</h1>",401)}
  loginFailures.delete(key);item.status="RUNNING";let sessionId=null;
  try{
   if(mode==="timed"){
    if(trustedSessions.size>=40){for(const [sid,s] of trustedSessions){if(["EXPIRED","REVOKED"].includes(currentSessionState(s)))trustedSessions.delete(sid)}}
    if(trustedSessions.size>=40)throw Error("Trusted session capacity reached");
    sessionId=rand(32);
    const s={clientId:item.clientId,profile,state:"VERIFYING",requestUntil:now()+300,validUntil:null,remaining:0,sourceHash:null,busy:false,attempts:0};
    trustedSessions.set(sessionId,s);
    s.sourceHash=await trustedSourceDigest(profile);
    if(s.state!=="VERIFYING")throw Error("Session was revoked");
    s.state="ACTIVE";s.validUntil=now()+durationMinutes*60;s.remaining=TRUSTED_MAX_CALLS;
    auditTrusted("activated",sessionId,{profile,duration_minutes:durationMinutes,expires_at:s.validUntil,max_calls:TRUSTED_MAX_CALLS});
    const response=await trustedDispatch("rian_eemf_run_trusted_command",{session_id:sessionId,...item.args},item.clientId);
    const executed=JSON.parse(response.content?.[0]?.text||"{}");
    if(!executed.execution||executed.execution.ok!==true)throw Error("Initial trusted command did not complete");
    item.status="COMPLETE";item.done=now();
    item.summary=JSON.stringify({...executed.execution,approval_session:{id:sessionId,profile,expires_at:s.validUntil,remaining_calls:s.remaining,duration_minutes:durationMinutes}}).slice(0,30000);
    return html('<h1>작업 완료 · 제한형 세션 시작</h1><p>'+escape(profile===PROJECT_PROFILE?"전용 파일 calculator.py·notes.md 수정 및 문법 검사":profile===SMOKE_PROFILE?"전용 테스트 파일 생성·수정 및 고정 테스트 실행":"허용된 조회 명령")+'을 '+durationMinutes+'분간 최대 60회 허용합니다. 남은 횟수: '+s.remaining+'. 다른 파일이나 일반 명령은 포함되지 않습니다.</p>');
   }
   const r=await relay(item.operation,item.args,true);
   item.status="COMPLETE";item.done=now();item.summary=JSON.stringify(r).slice(0,30000);
   return html('<h1>작업 완료</h1><p>이번 명령 1회만 승인했습니다. ChatGPT에서 작업 ID로 결과를 확인할 수 있습니다.</p>');
  }catch(err){
   if(sessionId){const s=trustedSessions.get(sessionId);if(s){s.state="REVOKED";s.remaining=0;auditTrusted("revoked_on_failure",sessionId)}}
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
