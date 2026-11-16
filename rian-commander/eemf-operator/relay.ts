
import {timingSafeEqual,randomUUID,createHmac,createHash} from "node:crypto";
const ADMIN=Bun.env.RIAN_ADMIN_TOKEN||"";
const KEYS=JSON.parse(Bun.env.RIAN_DEVICE_KEYS_JSON||"{}");
const CONFIGURED=ADMIN.length>=40&&Object.keys(KEYS).length>0&&!Object.values(KEYS).some(x=>typeof x!=="string"||x.length<40);
const devices=Object.keys(KEYS),queues=new Map(devices.map(x=>[x,[]])),seen=new Map(),jobs=new Map();
function equal(a,b){const x=Buffer.from(String(a||"")),y=Buffer.from(String(b||""));return x.length===y.length&&timingSafeEqual(x,y)}
function isAdmin(r){return equal(r.headers.get("Authorization"),"Bearer "+ADMIN)}
function isAgent(r){const n=r.headers.get("X-RIAN-Device")||"";return Object.hasOwn(KEYS,n)&&equal(r.headers.get("Authorization"),"Bearer "+KEYS[n])?n:null}
function reply(x,s=200){return Response.json(x,{status:s,headers:{"cache-control":"no-store"}})}
function error(x,s=400){return reply({error:x},s)}
function prune(){let now=Date.now();for(const [id,j] of jobs){if(now-j.created>180000&&j.state!=="done"){j.state="expired";j.result={error:"Job expired"}}if(now-j.created>900000)jobs.delete(id)}for(const n of devices)queues.set(n,queues.get(n).filter(id=>jobs.get(id)?.state==="pending"))}
function online(n){return Date.now()-(seen.get(n)||0)<55000}
function listing(){return devices.map(n=>({device:n,online:online(n),last_seen:seen.has(n)?new Date(seen.get(n)).toISOString():null,pending:queues.get(n).length}))}
function queue(n,act,args){if(!Object.hasOwn(KEYS,n))throw Error("Unknown device");if(!["status","list_directory","read_file","write_file","run_command"].includes(act))throw Error("Invalid action");if(!args||typeof args!=="object"||Array.isArray(args))throw Error("Invalid args");prune();if(queues.get(n).length>=3)throw Error("Queue full");const j={id:randomUUID(),device:n,action:act,arguments:args,state:"pending",result:null,created:Date.now()};jobs.set(j.id,j);queues.get(n).push(j.id);return j}
async function body(r){const s=await r.text();if(Buffer.byteLength(s)>600000)throw Error("Request too large");return s?JSON.parse(s):{}}
const dev={type:"string",description:"Exact computer name"};
function tools(){return [
{name:"rian_devices",description:"List devices and connection state",inputSchema:{type:"object",properties:{}}},
{name:"rian_status",description:"Read computer status",inputSchema:{type:"object",properties:{device:dev},required:["device"]}},
{name:"rian_list_directory",description:"List directory inside permitted root",inputSchema:{type:"object",properties:{device:dev,path:{type:"string"}},required:["device","path"]}},
{name:"rian_read_file",description:"Read UTF-8 file within permitted root",inputSchema:{type:"object",properties:{device:dev,path:{type:"string"}},required:["device","path"]}},
{name:"rian_write_file",description:"Write text file if enabled",inputSchema:{type:"object",properties:{device:dev,path:{type:"string"},content:{type:"string"},overwrite:{type:"boolean"}},required:["device","path","content"]}},
{name:"rian_run_command",description:"Execute program without shell if enabled",inputSchema:{type:"object",properties:{device:dev,argv:{type:"array",items:{type:"string"}},cwd:{type:"string"},timeout:{type:"integer"}},required:["device","argv"]}}]}
async function runTool(name,args,ownerApproved=false){if(name==="rian_devices")return{devices:listing()};if(args?.device==="DESKTOP-EEMFO3L"&&(name==="rian_write_file"||name==="rian_run_command")&&!ownerApproved)throw Error("EEMFO3L execution requires signed owner approval");const m={rian_status:"status",rian_list_directory:"list_directory",rian_read_file:"read_file",rian_write_file:"write_file",rian_run_command:"run_command"};if(!m[name])throw Error("Invalid tool");if(!online(args.device))throw Error("Device offline: "+args.device);const j=queue(args.device,m[name],Object.fromEntries(Object.entries(args).filter(([k])=>k!=="device")));for(let i=0;i<112;i++){if(j.state==="done")return j.result;if(j.state==="expired")throw Error("Job expired");await new Promise(r=>setTimeout(r,250))}throw Error("Job pending "+j.id)}
async function mcp(r){if(!isAdmin(r))return error("Unauthorized",401);const x=await body(r);const id=x.id;if(x.method==="notifications/initialized")return new Response(null,{status:202});let result;if(x.method==="initialize")result={protocolVersion:"2025-03-26",capabilities:{tools:{}},serverInfo:{name:"rian-commander",version:"0.2.0"}};else if(x.method==="tools/list")result={tools:tools()};else if(x.method==="ping")result={};else if(x.method==="tools/call"){try{result={content:[{type:"text",text:JSON.stringify(await runTool(x.params?.name,x.params?.arguments||{}))}]}}catch(e){result={content:[{type:"text",text:String(e.message)}],isError:true}}}else return reply({jsonrpc:"2.0",id:id??null,error:{code:-32601,message:"Unknown method"}});return id===undefined?new Response(null,{status:202}):reply({jsonrpc:"2.0",id,result})}



async function mcpAgent(r){
 const n=isAgent(r);if(!n)return error("Unauthorized",401);
 const x=await body(r),id=x.id;
 if(x.method==="notifications/initialized")return new Response(null,{status:202});
 let result;
 if(x.method==="initialize")result={protocolVersion:"2025-03-26",capabilities:{tools:{}},serverInfo:{name:"rian-commander-device",version:"0.2.2"}};
 else if(x.method==="tools/list"){
   const usable=tools().filter(t=>t.name!=="rian_devices");
   result={tools:usable.map(t=>{
     const props=Object.fromEntries(Object.entries(t.inputSchema.properties||{}).filter(pair=>pair[0]!=="device"));
     return {name:t.name,description:t.description+" (this device only)",inputSchema:{type:"object",properties:props,required:(t.inputSchema.required||[]).filter(k=>k!=="device")}};
   })};
 }
 else if(x.method==="ping")result={};
 else if(x.method==="tools/call"){
   try{const name=x.params?.name;if(name==="rian_devices")throw Error("Unavailable");result={content:[{type:"text",text:JSON.stringify(await runTool(name,{...(x.params?.arguments||{}),device:n}))}]}}
   catch(err){result={isError:true,content:[{type:"text",text:String(err.message).slice(0,500)}]}}
 }
 else return reply({jsonrpc:"2.0",id:id??null,error:{code:-32601,message:"Unknown method"}});
 return id===undefined?new Response(null,{status:202}):reply({jsonrpc:"2.0",id,result})
}




const FLEET_READER="DESKTOP-EEMFO3L";
const FLEET_TARGETS=["DESKTOP-EEMFO3L","DESKTOP-1QGT8D6","DESKTOP-S0UV4D1","Oui-MacStudio.local"];
function fleetTools(){
 const device={type:"string",enum:FLEET_TARGETS,description:"Exact registered computer name"};
 return [
  {name:"rian_fleet_devices",description:"List four registered machines and online state; read only",inputSchema:{type:"object",properties:{}}},
  {name:"rian_fleet_status",description:"Read status of one registered computer",inputSchema:{type:"object",properties:{device},required:["device"]}},
  {name:"rian_fleet_list_directory",description:"List a relative path beneath the computer's authorized home root; sensitive paths denied",inputSchema:{type:"object",properties:{device,path:{type:"string"}},required:["device","path"]}},
  {name:"rian_fleet_read_file",description:"Read a UTF-8 text file within authorized home root; sensitive paths denied",inputSchema:{type:"object",properties:{device,path:{type:"string"}},required:["device","path"]}}
 ];
}
function safeFleetPath(path){
 if(typeof path!=="string"||path.length>512||!path.trim()||path.includes("\0"))throw Error("Invalid path");
 const clean=path.replaceAll("\\","/");
 if(clean.startsWith("/")||clean.startsWith("//")||clean.includes(":")||clean.startsWith("~"))throw Error("Only relative paths are allowed");
 const segments=clean.split("/").filter(x=>x!==""&&x!==".");
 if(segments.some(x=>x===".."))throw Error("Path traversal denied");
 const low=segments.map(x=>x.toLowerCase());
 const blocked=[".ssh",".aws",".gnupg",".kube",".git",".codex",".claude",".config","appdata","application support","keychain","cookies","login data",".env","secrets","credentials","config.json","token.json","ntuser.dat","id_rsa","id_ed25519","mcp_readonly_1q_bridge.py","agent.ps1","agent.py"];
 if(low.some(x=>blocked.includes(x)||x.startsWith(".env.")||x.endsWith(".pem")||x.endsWith(".key")||x.endsWith(".p12")||x.endsWith(".pfx")))throw Error("Sensitive path denied");
 return path;
}
async function fleetCall(name,args){
 if(!args||typeof args!=="object"||Array.isArray(args))throw Error("Invalid arguments");
 if(name==="rian_fleet_devices")return {devices:listing().filter(x=>FLEET_TARGETS.includes(x.device))};
 if(!FLEET_TARGETS.includes(args.device))throw Error("Target outside read-only fleet");
 let tool;
 if(name==="rian_fleet_status")tool="rian_status";
 else if(name==="rian_fleet_list_directory")tool="rian_list_directory";
 else if(name==="rian_fleet_read_file")tool="rian_read_file";
 else throw Error("Read-only fleet: operation denied");
 const cleanArgs=tool==="rian_status"?{device:args.device}:{device:args.device,path:safeFleetPath(args.path)};
 const result=await runTool(tool,cleanArgs);
 if(tool==="rian_read_file"&&JSON.stringify(result).length>100000)throw Error("File too large for fleet read-only access");
 return result;
}



function isGateway(req){
 const given=req.headers.get("Authorization")||"";
 const token=Bun.env.RIAN_READONLY_GATEWAY_TOKEN||"";
 return token.length>=48&&equal(given,"Bearer "+token);
}
async function mcpFleetGateway(req){
 if(!isGateway(req))return error("Unauthorized",401);
 const x=await body(req),id=x.id;
 if(x.method==="notifications/initialized")return new Response(null,{status:202});
 let result;
 if(x.method==="initialize")result={protocolVersion:"2025-03-26",capabilities:{tools:{}},serverInfo:{name:"rian-commander-gateway-readonly",version:"0.3.1"}};
 else if(x.method==="tools/list")result={tools:fleetTools()};
 else if(x.method==="ping")result={};
 else if(x.method==="tools/call"){
  try{
   const data=await fleetCall(x.params?.name,x.params?.arguments||{});
   result={content:[{type:"text",text:JSON.stringify(data)}]};
  }catch(e){result={isError:true,content:[{type:"text",text:String(e.message).slice(0,250)}]}}
 }else return reply({jsonrpc:"2.0",id:id??null,error:{code:-32601,message:"Unknown method"}});
 return id===undefined?new Response(null,{status:202}):reply({jsonrpc:"2.0",id,result});
}

async function mcpFleetReadOnly(r){
 if(isAgent(r)!==FLEET_READER)return error("Unauthorized",401);
 const x=await body(r),id=x.id;
 if(x.method==="notifications/initialized")return new Response(null,{status:202});
 let result;
 if(x.method==="initialize")result={protocolVersion:"2025-03-26",capabilities:{tools:{}},serverInfo:{name:"rian-commander-fleet-readonly",version:"0.3.0"}};
 else if(x.method==="tools/list")result={tools:fleetTools()};
 else if(x.method==="ping")result={};
 else if(x.method==="tools/call"){
  try{
   const value=await fleetCall(x.params?.name,x.params?.arguments||{});
   result={content:[{type:"text",text:JSON.stringify(value)}]};
  }catch(e){result={isError:true,content:[{type:"text",text:String(e.message).slice(0,250)}]}}
 }else return reply({jsonrpc:"2.0",id:id??null,error:{code:-32601,message:"Unknown method"}});
 return id===undefined?new Response(null,{status:202}):reply({jsonrpc:"2.0",id,result});
}

async function mcpRead1Q(r){
  if(isAgent(r)!=="DESKTOP-EEMFO3L")return error("Unauthorized",401);
  const x=await body(r),id=x.id;
  if(x.method==="notifications/initialized")return new Response(null,{status:202});
  let result;
  if(x.method==="initialize")result={protocolVersion:"2025-03-26",capabilities:{tools:{}},serverInfo:{name:"rian-commander-1q-readonly",version:"0.2.3"}};
  else if(x.method==="tools/list"){
    result={tools:[
      {name:"rian_1q_status",description:"Read status of DESKTOP-1QGT8D6 (read-only)",inputSchema:{type:"object",properties:{}}},
      {name:"rian_1q_list_directory",description:"List files under allowed root on DESKTOP-1QGT8D6 (read-only)",inputSchema:{type:"object",properties:{path:{type:"string"}},required:["path"]}},
      {name:"rian_1q_read_file",description:"Read UTF-8 text file under allowed root on DESKTOP-1QGT8D6 (read-only)",inputSchema:{type:"object",properties:{path:{type:"string"}},required:["path"]}}
    ]};
  }
  else if(x.method==="ping")result={};
  else if(x.method==="tools/call"){
    try{
      const n=x.params?.name,args=x.params?.arguments||{};
      const action={rian_1q_status:"rian_status",rian_1q_list_directory:"rian_list_directory",rian_1q_read_file:"rian_read_file"}[n];
      if(!action)throw Error("Operation not permitted: read-only 1Q scope");
      if(!args||typeof args!=="object"||Array.isArray(args))throw Error("Invalid arguments");
      const safeArgs=action==="rian_status"?{}:{path:args.path};
      if(action!=="rian_status"&&(typeof safeArgs.path!=="string"||!safeArgs.path.trim()))throw Error("Path required");
      const output=await runTool(action,{device:"DESKTOP-1QGT8D6",...safeArgs});
      result={content:[{type:"text",text:JSON.stringify(output)}]};
    }catch(ex){
      result={isError:true,content:[{type:"text",text:String(ex.message).slice(0,250)}]};
    }
  }else return reply({jsonrpc:"2.0",id:id??null,error:{code:-32601,message:"Unknown method"}});
  return id===undefined?new Response(null,{status:202}):reply({jsonrpc:"2.0",id,result});
}


/* Privileged EEMFO3L-only bridge, protected by a dedicated gateway key.
   Never expose the relay ADMIN token to the OAuth gateway.
   Existing four-PC read-only tools are unchanged. */
const EEMF_DEVICE="DESKTOP-EEMFO3L";
const EEMF_TOKEN=Bun.env.RIAN_EEMF_GATEWAY_TOKEN||"";
const EEMF_APPROVAL_SECRET=Bun.env.RIAN_EEMF_APPROVAL_SECRET||"";
const eemfApprovalUsed=new Map();
function checkEEMFApproval(req,name,args){
 const proof=req.headers.get("x-rian-eemf-approved")||"";
 if(EEMF_APPROVAL_SECRET.length<48||proof.length>2000)return false;
 const parts=proof.split(".");
 if(parts.length!==2||!/^[A-Za-z0-9_-]+$/.test(parts[0])||!/^[a-f0-9]{64}$/.test(parts[1]))return false;
 const expected=createHmac("sha256",EEMF_APPROVAL_SECRET).update(parts[0]).digest("hex");
 if(!equal(expected,parts[1]))return false;
 let claim;try{claim=JSON.parse(Buffer.from(parts[0],"base64url").toString("utf8"))}catch{return false}
 const now=Math.floor(Date.now()/1000);
 if(!claim||claim.name!==name||!Number.isInteger(claim.exp)||claim.exp<now||claim.exp>now+65||typeof claim.nonce!=="string"||!/^[a-f0-9]{32}$/.test(claim.nonce)||claim.sha256!==createHash("sha256").update(JSON.stringify(args)).digest("hex"))return false;
 for(const [key,value] of eemfApprovalUsed){if(value<=now)eemfApprovalUsed.delete(key)}
 if(eemfApprovalUsed.has(claim.nonce))return false;
 eemfApprovalUsed.set(claim.nonce,claim.exp);
 return true;
}

function isEEMFGateway(req){
 return EEMF_TOKEN.length>=48&&equal(req.headers.get("Authorization"),"Bearer "+EEMF_TOKEN);
}
const eemfNames={
 rian_eemf_status:"rian_status",
 rian_eemf_list_directory:"rian_list_directory",
 rian_eemf_read_file:"rian_read_file",
 rian_eemf_run_command:"rian_run_command",
 rian_eemf_write_file:"rian_write_file"
};
function eemfRelativePath(raw){
 if(typeof raw!=="string"||!raw.trim()||raw.length>512||/[\x00-\x1f]/.test(raw))throw Error("Invalid EEMF path");
 const normal=raw.replaceAll("\\","/");
 const parts=normal.toLowerCase().split("/");
 if(normal.startsWith("/")||normal.startsWith("~")||normal.includes(":")||parts.includes(".."))throw Error("EEMF path outside home");
 const blocked=[".ssh",".aws",".gnupg",".kube",".codex",".claude",".git","appdata","credentials","secrets","ntuser.dat","token.json",".env"];
 if(parts.some(v=>blocked.includes(v)||/\.(pem|pfx|p12|key)$/.test(v)))throw Error("Sensitive EEMF path");
 return normal;
}
function eemfArgs(name,raw){
 if(!Object.hasOwn(eemfNames,name)||!raw||typeof raw!=="object"||Array.isArray(raw))throw Error("EEMF tool denied");
 if(Object.hasOwn(raw,"device"))throw Error("Device override denied");
 const keys=Object.keys(raw);
 if(name==="rian_eemf_status"){if(keys.length)throw Error("Unexpected input");return {}}
 if(name==="rian_eemf_list_directory"||name==="rian_eemf_read_file"){
  if(keys.length!==1||keys[0]!=="path")throw Error("Unexpected input");
  return {path:eemfRelativePath(raw.path)};
 }
 if(name==="rian_eemf_write_file"){
  if(keys.some(x=>!["path","content","overwrite"].includes(x))||typeof raw.content!=="string"||raw.content.length>12000||raw.content.includes("\0")||raw.overwrite!==undefined&&typeof raw.overwrite!=="boolean")throw Error("Invalid write");
  return {path:eemfRelativePath(raw.path),content:raw.content,overwrite:raw.overwrite===true};
 }
 if(name==="rian_eemf_run_command"){
  if(keys.some(x=>!["argv","cwd","timeout"].includes(x)))throw Error("Unexpected command input");
  if(!Array.isArray(raw.argv)||raw.argv.length<1||raw.argv.length>20||raw.argv.some(x=>typeof x!=="string"||x.length>500||!x.trim()||/[\x00-\x1f]/.test(x)))throw Error("Invalid argv");
  if(raw.cwd!==undefined&&typeof raw.cwd!=="string")throw Error("Invalid cwd");
  if(raw.timeout!==undefined&&(!Number.isInteger(raw.timeout)||raw.timeout<1||raw.timeout>90))throw Error("Invalid timeout");
  return {argv:raw.argv,cwd:raw.cwd?eemfRelativePath(raw.cwd):undefined,timeout:raw.timeout||30};
 }
 throw Error("EEMF operation denied");
}
async function mcpEEMFOwner(req){
 if(!isEEMFGateway(req))return error("Unauthorized",401);
 const x=await body(req),id=x.id;
 if(x.method==="notifications/initialized")return new Response(null,{status:202});
 let result;
 if(x.method==="initialize")result={protocolVersion:"2025-03-26",capabilities:{tools:{}},serverInfo:{name:"rian-commander-eemf-owner-bridge",version:"0.4.0"}};
 else if(x.method==="tools/list")result={tools:[]}; // Not a general discovery endpoint.
 else if(x.method==="ping")result={};
 else if(x.method==="tools/call"){
  try{
   const name=x.params?.name;
   const args=eemfArgs(name,x.params?.arguments||{});
   const isSensitive=(name==="rian_eemf_run_command"||name==="rian_eemf_write_file");
   if(isSensitive&&!checkEEMFApproval(req,name,args))throw Error("Owner approval proof required");
   const raw=await runTool(eemfNames[name],{device:EEMF_DEVICE,...args},isSensitive);
   result={content:[{type:"text",text:JSON.stringify(raw)}]};
  }catch(e){result={isError:true,content:[{type:"text",text:String(e.message).slice(0,250)}]}}
 }else return reply({jsonrpc:"2.0",id:id??null,error:{code:-32601,message:"Unknown method"}});
 return id===undefined?new Response(null,{status:202}):reply({jsonrpc:"2.0",id,result});
}

Bun.serve({hostname:"0.0.0.0",port:Number(Bun.env.PORT||3000),async fetch(r){try{prune();const p=new URL(r.url).pathname,method=r.method;
if(p==="/"&&method==="GET")return new Response('<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RIAN Commander</title><body style="font:16px system-ui;margin:8vh auto;padding:0 24px;max-width:650px;line-height:1.7"><h1>RIAN Commander</h1><p>중앙 연결 서버 상태: <strong>'+ (CONFIGURED?'인증 설정 완료':'인증 설정 대기') +'</strong></p><p>이 주소는 PC 화면을 원격 조작하는 웹페이지가 아니라 각 PC 에이전트의 연결을 중계하는 서버입니다.</p><p>관리자가 Railway에서 인증 환경변수를 등록한 뒤 PC별 설치 프로그램을 실행해야 연결됩니다.</p><p><a href="https://railway.com/dashboard">Railway 관리 화면</a></p></body></html>',{headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store"}});
if(p==="/health"&&method==="GET")return reply({ok:CONFIGURED,app:"RIAN Commander relay",version:"0.2.1",configured:CONFIGURED},CONFIGURED?200:503);
if(!CONFIGURED)return error("Server setup incomplete: required credentials are not configured",503);
if(p==="/mcp"&&method==="POST")return await mcp(r);
if(p==="/mcp/readonly-1q"&&method==="POST")return await mcpRead1Q(r);
if(p==="/mcp/fleet-readonly"&&method==="POST")return await mcpFleetReadOnly(r);
if(p==="/mcp/gateway-readonly"&&method==="POST")return await mcpFleetGateway(r);
if(p==="/mcp/eemf-owner"&&method==="POST")return await mcpEEMFOwner(r);
if(p==="/mcp/device"&&method==="POST")return await mcpAgent(r);
if(p==="/mcp"&&method==="GET")return reply({name:"rian-commander",transport:"Streamable HTTP",version:"0.2.0"});
if(p==="/v1/poll"&&method==="POST"){const n=isAgent(r);if(!n)return error("Unauthorized",401);if(!online(n))console.info("RIAN_AGENT_ONLINE",n);seen.set(n,Date.now());const q=queues.get(n);while(q.length){const j=jobs.get(q.shift());if(j&&j.state==="pending"){j.state="running";return reply({job:{id:j.id,action:j.action,arguments:j.arguments}})}}return reply({job:null})}
if(p==="/v1/result"&&method==="POST"){const n=isAgent(r);if(!n)return error("Unauthorized",401);const x=await body(r),j=jobs.get(x.id);if(!j||j.device!==n)return error("Unknown job",404);if(j.state==="done")return reply({ok:true});if(j.state!=="running")return error("Invalid job state",409);j.result=x.result;j.state="done";seen.set(n,Date.now());return reply({ok:true})}
if(p==="/v1/devices"&&method==="GET"){if(!isAdmin(r))return error("Unauthorized",401);return reply({devices:listing()})}
if(p==="/v1/jobs"&&method==="POST"){if(!isAdmin(r))return error("Unauthorized",401);const x=await body(r),j=queue(x.device,x.action,x.arguments||{});return reply({job_id:j.id,online:online(x.device)},202)}
if(p.startsWith("/v1/jobs/")&&method==="GET"){if(!isAdmin(r))return error("Unauthorized",401);const j=jobs.get(p.slice(9));return j?reply({id:j.id,device:j.device,state:j.state,result:j.result}):error("Unknown job",404)}
return error("Not found",404)}catch(e){return error(String(e.message))}}});
