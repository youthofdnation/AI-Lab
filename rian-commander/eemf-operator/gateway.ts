
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
{name:"rian_eemf_request_command",description:"Request an EEMFO3L command or submit RIAN_DEV_SCOPE_V1 to create a one-time owner-approved, repository-specific Git/test/edit session. Exact allowed commands auto-reuse active session; no arbitrary shell or push/delete.",inputSchema:{type:"object",properties:{argv:{type:"array",items:{type:"string"}},cwd:{type:"string"},timeout:{type:"integer"},approval_mode:{type:"string",enum:["choose","each"]}},required:["argv"],additionalProperties:false}},
{name:"rian_eemf_request_write",description:"DRAFT a write to a permitted text file on EEMFO3L requiring browser approval. Does not write yet.",inputSchema:{type:"object",properties:{path:{type:"string"},content:{type:"string"},overwrite:{type:"boolean"}},required:["path","content"],additionalProperties:false}},
{name:"rian_eemf_request_trusted_session",description:"Request a user-selected 1-60 minute restricted trust session, owner password approval once: Proton title search, Outlook metadata search, or limited developer version checks. No writes or arbitrary shell.",inputSchema:{type:"object",properties:{profile:{type:"string",enum:["proton-local-readonly-v1","outlook-local-metadata-v1","dev-version-checks-v1","dev-sandbox-smoke-v1","dev-workspace-edit-v1","dev-project-history-v2"]}},additionalProperties:false}},
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
 if(typeof client!=="string"||!client.startsWith("rian.")||!([PROJECT_FILE,PROJECT_NOTES].includes(path)||v2MutablePath(path))||typeof content!=="string"||Buffer.byteLength(content,"utf8")>PROJECT_MAX_BYTES)return;
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

const V2_PROFILE="dev-project-history-v2",V2_CWD="Documents",V2_ROOT="Documents/RIAN-Commander-Smoke";
const V2_HISTORY=V2_ROOT+"/rian_history.json",V2_RUNNER_FILE=V2_ROOT+"/_rian_runner.py";
const V2_HISTORY_INIT='{"version":1,"entries":[]}';
const V2_RUNNER="\"\"\"RIAN Commander isolated calculator-test runner.\n\nRestricted acceptance fixture, not a general-purpose sandbox. This script\ndoes not authorize running arbitrary Python code on the owner device.\n\"\"\"\nfrom pathlib import Path\nimport ast\nimport hashlib\nimport sys\nimport types\nimport unittest\n\nROOT = Path(__file__).resolve().parent\nSOURCE = ROOT / \"calculator.py\"\nTEST = ROOT / \"test_calculator.py\"\nTEST_SHA256 = \"6fb38286f1452c6d5745098123c9793e2c62c14248d49284edf5b45cc82b2161\"\nALLOWED = (\n    ast.Module, ast.FunctionDef, ast.arguments, ast.arg, ast.Name, ast.Load,\n    ast.Store, ast.Expr, ast.Constant, ast.If, ast.BoolOp, ast.Or, ast.Compare,\n    ast.Lt, ast.Raise, ast.Call, ast.Assign, ast.BinOp, ast.Mult, ast.Add,\n    ast.Return,\n)\nNAMES = {\"subtotal\", \"tax_rate\", \"tax_amount\", \"float\", \"ValueError\"}\n\ndef validate(tree):\n    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):\n        raise ValueError(\"exactly one calculator function required\")\n    fn = tree.body[0]\n    if (fn.name != \"total_with_tax\" or len(fn.args.args) != 2\n            or [a.arg for a in fn.args.args] != [\"subtotal\", \"tax_rate\"]\n            or fn.decorator_list or fn.args.vararg or fn.args.kwarg):\n        raise ValueError(\"unsupported calculator API\")\n    for node in ast.walk(tree):\n        if type(node) not in ALLOWED:\n            raise ValueError(\"disallowed syntax: \" + type(node).__name__)\n        if isinstance(node, ast.Name) and node.id not in NAMES:\n            raise ValueError(\"disallowed name: \" + node.id)\n        if isinstance(node, ast.Call) and (\n                not isinstance(node.func, ast.Name)\n                or node.func.id != \"ValueError\"\n                or len(node.args) != 1 or node.keywords\n                or not isinstance(node.args[0], ast.Constant)\n                or not isinstance(node.args[0].value, str)):\n            raise ValueError(\"disallowed function call\")\n        if isinstance(node, ast.Assign) and (\n                len(node.targets) != 1\n                or not isinstance(node.targets[0], ast.Name)\n                or node.targets[0].id != \"tax_amount\"):\n            raise ValueError(\"disallowed assignment\")\n        if isinstance(node, ast.If) and (\n                node.orelse or len(node.body) != 1\n                or not isinstance(node.body[0], ast.Raise)):\n            raise ValueError(\"unsupported branch\")\n        if isinstance(node, ast.Constant) and type(node.value) not in (str, int, float):\n            raise ValueError(\"unsupported constant\")\n    if not isinstance(fn.body[-1], ast.Return):\n        raise ValueError(\"return required\")\n\ndef main():\n    for path in (SOURCE, TEST):\n        if path.is_symlink() or not path.is_file() or path.stat().st_size > 5000:\n            raise ValueError(\"unsafe source or test path\")\n    source = SOURCE.read_text(encoding=\"utf-8\").replace(\"\\r\\n\", \"\\n\")\n    tests = TEST.read_text(encoding=\"utf-8\").replace(\"\\r\\n\", \"\\n\")\n    if hashlib.sha256(tests.encode(\"utf-8\")).hexdigest() != TEST_SHA256:\n        raise ValueError(\"pinned unittest fixture changed\")\n    tree = ast.parse(source, filename=\"calculator.py\")\n    validate(tree)\n\n    module = types.ModuleType(\"calculator\")\n    exec(compile(tree, \"calculator.py\", \"exec\"), module.__dict__)\n    sys.modules[\"calculator\"] = module\n    test_module = types.ModuleType(\"rian_pinned_unittest\")\n    exec(compile(tests, \"test_calculator.py\", \"exec\"), test_module.__dict__)\n    suite = unittest.defaultTestLoader.loadTestsFromModule(test_module)\n    if suite.countTestCases() != 4:\n        raise ValueError(\"unexpected test count\")\n    result = unittest.TextTestRunner(verbosity=2).run(suite)\n    return 0 if result.wasSuccessful() else 1\n\nif __name__ == \"__main__\":\n    try:\n        sys.exit(main())\n    except Exception as error:\n        print(\"RIAN_RUNNER_BLOCKED: \" + str(error), file=sys.stderr)\n        sys.exit(2)\n";
const V2_BOOT=["python","-I","-S","-c","print('RIAN_PROJECT_V2_READY')"];
const V2_RUN=["python","-I","-S","RIAN-Commander-Smoke/_rian_runner.py"];
const V2_POLICY_PIN="v2:project-top-level-python-md|pinned-tests|AST-validated-runner|persisted-prior-text|2026-11-18";
const V2_MAX_SOURCE_BYTES=5000,V2_MAX_HISTORY_BYTES=11000,V2_MAX_EDITABLE_FILES=8;
let v2Busy=false;
export function v2MutablePath(path){
 if(typeof path!=="string"||!path.startsWith(V2_ROOT+"/")||path.length>220)return false;
 const suffix=path.slice(V2_ROOT.length+1);
 if(!/^[a-z][a-z0-9_-]{0,40}\.(?:py|md)$/.test(suffix))return false;
 if(suffix.startsWith("test_")||suffix==="runner.py"||suffix==="history.py")return false;
 return true;
}
export function v2WriteAllowed(a){
 if(!a||typeof a!=="object"||Array.isArray(a)||Object.keys(a).some(k=>!["path","content","overwrite"].includes(k))||typeof a.content!=="string"||a.content.includes("\0"))return false;
 if(a.path===V2_RUNNER_FILE)return a.overwrite===false&&a.content===V2_RUNNER;
 if(a.path===V2_HISTORY)return a.overwrite===false&&a.content===V2_HISTORY_INIT;
 return v2MutablePath(a.path)&&a.content.trim().length>0&&Buffer.byteLength(a.content,"utf8")<=V2_MAX_SOURCE_BYTES&&(a.overwrite===true||a.overwrite===false);
}
function v2Sha(content){return createHash("sha256").update(content,"utf8").digest("hex")}
function v2ValidateLedger(data){
 if(!data||typeof data!=="object"||data.version!==1||!Array.isArray(data.entries)||data.entries.length>7)throw Error("Invalid project history ledger");
 for(const entry of data.entries){
  if(!entry||typeof entry!=="object"||!v2MutablePath(entry.path)||!["PREPARED","COMPLETE","ABORTED"].includes(entry.state)||
    !Number.isInteger(entry.at)||entry.at<0||
    typeof entry.before!=="string"||Buffer.byteLength(entry.before,"utf8")>V2_MAX_SOURCE_BYTES||
    typeof entry.before_sha!=="string"||!/^[a-f0-9]{64}$/.test(entry.before_sha)||
    typeof entry.after_sha!=="string"||!/^[a-f0-9]{64}$/.test(entry.after_sha)||
    (entry.before!==""&&v2Sha(entry.before)!==entry.before_sha))throw Error("Invalid history entry");
 }
 return data;
}
async function v2ReadLedger(){
 const data=await relay("rian_eemf_read_file",{path:V2_HISTORY});
 const content=data?.result?.content;
 if(typeof content!=="string"||Buffer.byteLength(content,"utf8")>V2_MAX_HISTORY_BYTES)throw Error("Project history not initialized or too large");
 try{return v2ValidateLedger(JSON.parse(content))}catch(e){throw Error("Project history unreadable or invalid: "+String(e.message))}
}
async function v2SaveLedger(ledger){
 v2ValidateLedger(ledger);
 let serialized=JSON.stringify(ledger);
 while(Buffer.byteLength(serialized,"utf8")>V2_MAX_HISTORY_BYTES-500&&ledger.entries.length>1){
  ledger.entries.shift();serialized=JSON.stringify(ledger);
 }
 if(Buffer.byteLength(serialized,"utf8")>V2_MAX_HISTORY_BYTES-500)throw Error("History too large; write stopped");
 await relay("rian_eemf_write_file",{path:V2_HISTORY,content:serialized,overwrite:true},true);
 const r=await relay("rian_eemf_read_file",{path:V2_HISTORY});
 if(r?.result?.content!==serialized)throw Error("Durable history readback failed");
}
async function v2RecoverLedger(ledger){
 const last=ledger.entries.at(-1);
 if(!last||last.state!=="PREPARED")return;
 const r=await relay("rian_eemf_read_file",{path:last.path});
 const live=r?.result?.content;
 if(typeof live!=="string")throw Error("Pending history cannot be recovered");
 const hash=v2Sha(live);
 if(hash===last.after_sha)last.state="COMPLETE";
 else if(hash===last.before_sha)last.state="ABORTED";
 else throw Error("History conflict: source diverged; manual review required");
 await v2SaveLedger(ledger);
}
async function v2CheckPath(path){
 if(!v2MutablePath(path))throw Error("Only owner-approved project files may be edited");
 const dir=await relay("rian_eemf_list_directory",{path:V2_ROOT});
 const entries=dir?.result?.entries;
 if(!Array.isArray(entries)||entries.length>400)throw Error("Invalid project folder");
 const filename=path.slice(V2_ROOT.length+1);
 const existing=entries.find(x=>x.name===filename);
 if(existing&&existing.type!=="file")throw Error("Target is not a regular file");
 const editable=entries.filter(x=>x.type==="file"&&v2MutablePath(V2_ROOT+"/"+x.name));
 if(editable.length>V2_MAX_EDITABLE_FILES)throw Error("Project file-count limit exceeded");
 return {exists:!!existing,count:editable.length};
}
async function v2CheckPathOnPC(path){
 const relative=path.slice("Documents/".length);
 const script="from pathlib import Path;import sys;r=Path('RIAN-Commander-Smoke');p=Path(sys.argv[1]);assert not r.is_symlink() and r.is_dir() and p.parent.resolve()==r.resolve() and not p.is_symlink();print('PATH_OK')";
 const args={argv:["python","-I","-S","-c",script,relative],cwd:V2_CWD,timeout:20};
 const out=await relay("rian_eemf_run_command",args,true);
 if(out?.result?.exit_code!==0||!String(out?.result?.stdout||"").includes("PATH_OK"))throw Error("PC canonical-path/symlink guard denied");
}
async function v2Write(sessionId,args,clientId){
 const sess=ownedSession(sessionId,clientId);
 if(sess.profile!==V2_PROFILE||currentSessionState(sess)!=="ACTIVE"||sess.remaining<=0||!v2WriteAllowed(args))throw Error("No project edit grant or write out of scope");
 if(sess.busy||v2Busy)throw Error("Another project operation is running");
 sess.busy=true;v2Busy=true;
 try{
  if(sess.sourceHash!==await trustedSourceDigest(V2_PROFILE)){sess.state="REVOKED";sess.remaining=0;throw Error("Project policy changed; session revoked")}
  if(args.path===V2_RUNNER_FILE||args.path===V2_HISTORY){
   const files=await relay("rian_eemf_list_directory",{path:V2_ROOT});
   const name=args.path.slice(V2_ROOT.length+1);
   if(files?.result?.entries?.some(x=>x.name===name))throw Error("Reserved project file already exists");
   if(currentSessionState(sess)!=="ACTIVE")throw Error("Session expired");
   sess.remaining--;await relay("rian_eemf_write_file",args,true);
   const checked=await relay("rian_eemf_read_file",{path:args.path});
   if(checked?.result?.content!==args.content)throw Error("Bootstrap file readback failure");
   auditTrusted("v2_project_bootstrap",sessionId,{file:name,remaining:sess.remaining});
   return sessionReply({profile:V2_PROFILE,device,path:args.path,state:currentSessionState(sess),write_verified:true,remaining_calls:sess.remaining,sha256:v2Sha(args.content)});
  }
  const pathState=await v2CheckPath(args.path);
  if(args.overwrite!==pathState.exists)throw Error("Create/overwrite flag does not match remote file state");
  if(!args.overwrite&&pathState.count>=V2_MAX_EDITABLE_FILES)throw Error("Project file count at limit");
  await v2CheckPathOnPC(args.path);
  let previous="",shaBefore=v2Sha(previous);
  if(args.overwrite){
   const snapshot=projectSnapshots.get(projectKey(clientId,args.path));
   if(!snapshot||snapshot.until<=now())throw Error("Read source file in chat before editing: snapshot missing or expired");
   const r=await relay("rian_eemf_read_file",{path:args.path});
   previous=r?.result?.content;
   if(typeof previous!=="string"||v2Sha(previous)!==snapshot.hash)throw Error("CAS conflict: file changed after last read");
   shaBefore=v2Sha(previous);
   if(previous===args.content)return sessionReply({profile:V2_PROFILE,path:args.path,state:currentSessionState(sess),no_change:true,sha256:shaBefore,remaining_calls:sess.remaining});
  }
  const ledger=await v2ReadLedger();
  await v2RecoverLedger(ledger);
  const newSha=v2Sha(args.content);
  const rollback=ledger.entries.some(e=>e.state==="COMPLETE"&&e.path===args.path&&e.before_sha===newSha&&e.after_sha===shaBefore);
  const log={path:args.path,at:now(),before:previous,before_sha:shaBefore,after_sha:newSha,state:"PREPARED",rollback,client_digest:projectDigest(clientId).slice(0,12)};
  ledger.entries.push(log);
  while(ledger.entries.length>6)ledger.entries.shift();
  await v2SaveLedger(ledger);
  if(currentSessionState(sess)!=="ACTIVE")throw Error("Session expired after durable history preparation");
  if(args.overwrite){
   const check=await relay("rian_eemf_read_file",{path:args.path});
   if(v2Sha(check?.result?.content||"")!==shaBefore)throw Error("File changed during patch preparation");
  }
  sess.remaining--;
  auditTrusted("v2_patch_submitted",sessionId,{file:args.path.slice(V2_ROOT.length+1),remaining:sess.remaining,rollback});
  await relay("rian_eemf_write_file",{path:args.path,content:args.content,overwrite:args.overwrite},true);
  const final=await relay("rian_eemf_read_file",{path:args.path});
  if(final?.result?.content!==args.content)throw Error("Source write readback differs from requested content");
  log.state="COMPLETE";
  await v2SaveLedger(ledger);
  projectTrackRead(clientId,args.path,args.content);
  auditTrusted("v2_patch_completed",sessionId,{remaining:sess.remaining,rollback});
  return sessionReply({device,profile:V2_PROFILE,path:args.path,state:currentSessionState(sess),write_verified:true,rollback,remaining_calls:sess.remaining,precondition_sha256:shaBefore,sha256:newSha,history_file:V2_HISTORY,history_records:ledger.entries.length,diff:projectDiff(previous,args.content)});
 }finally{sess.busy=false;v2Busy=false}
}
async function v2CheckRunner(){
 const [r,t]=await Promise.all([relay("rian_eemf_read_file",{path:V2_RUNNER_FILE}),relay("rian_eemf_read_file",{path:SMOKE_TEST_PATH})]);
 if(r?.result?.content!==V2_RUNNER||t?.result?.content!==SMOKE_TEST)throw Error("Pinned unit test runner or fixture changed; execution blocked");
 await v2CheckPathOnPC(V2_ROOT+"/calculator.py");
}


const DEV_TASK_PROFILE="dev-task-scope-v1",DEV_TASK_MARKER="RIAN_DEV_SCOPE_V1";
const DEV_TASK_ROOT="Documents/RIAN-Commander-Dev",DEV_TASK_HOME="Documents",DEV_TASK_POLICY="v1|owner-approved-manifest|one-repo-one-pr|no-push-clean-reset-delete-deploy|2026-11-18";
const DEV_TASK_MAX_BYTES=11500;
const DEV_TASK_SETUP_SCRIPT="from pathlib import Path;import sys;r=Path('RIAN-Commander-Dev');assert not r.is_symlink();r.mkdir(exist_ok=True);assert r.resolve().parent==Path.cwd().resolve();p=r/sys.argv[1];assert not p.exists() and not p.is_symlink();p.mkdir();print('RIAN_DEV_READY')";
const DEV_TASK_GUARD_SCRIPT="from pathlib import Path;import sys;r=Path('RIAN-Commander-Dev');p=r/sys.argv[1];assert r.is_dir() and not r.is_symlink() and r.resolve().parent==Path.cwd().resolve() and p.is_dir() and not p.is_symlink() and p.resolve().parent==r.resolve();assert all(not (p/x).is_symlink() for x in ('repo','tree'));print('RIAN_DEV_GUARD_OK')";
const DEV_TASK_TOOLCHAIN_SCRIPT="import shutil;from pathlib import Path; b=Path.home()/'.bun'/'bin'/'bun.exe'; names=('python','git','node','bun'); print('RIAN_TOOLCHAIN_V1 '+','.join(name+'='+('discoverable' if shutil.which(name) else 'not_in_path') for name in names)+',bun_user='+('present' if b.is_file() and not b.is_symlink() else 'absent'))";
const DEV_TASK_FILE_GUARD_SCRIPT="from pathlib import Path;import sys;r=Path('RIAN-Commander-Dev')/sys.argv[1]/'tree';p=r/sys.argv[2];assert r.is_dir() and not r.is_symlink() and p.parent.resolve().is_relative_to(r.resolve());assert not p.is_symlink() and all(not x.is_symlink() for x in p.parents if x.exists());print('RIAN_DEV_FILE_OK')";
export function devTaskSafePath(path,extension){
 if(typeof path!=="string"||path.length>180||path.startsWith("/")||path.includes("\\")||path.includes(":"))return false;
 const segments=path.split("/");
 if(segments.length>7||segments.length<2||segments.some(x=>!x||x==="."||x===".."||x.startsWith(".")||!/^[A-Za-z0-9_.-]+$/.test(x)))return false;
 if(segments.some(x=>["node_modules",".git",".github","secrets","credentials","dist","build","appdata"].includes(x.toLowerCase())))return false;
 const filename=segments.at(-1);
 if(filename.startsWith("test_")&&extension==="edit")return false;
 if(extension==="test")return ((path.startsWith("tests/")||path.includes("/tests/"))&&/(^|\/)test_[a-zA-Z0-9_-]+\.py$/.test(path))||/(^|\/)[A-Za-z0-9_-]+\.test\.(?:js|ts)$/.test(path);
 return /\.(?:py|ts|tsx|js|jsx|md|json|yaml|yml)$/.test(filename)&&!path.startsWith("tests/");
}
export function devTaskParseScope(raw){
 if(!raw||typeof raw!=="object"||Array.isArray(raw)||Object.keys(raw).some(k=>!["argv","cwd","timeout"].includes(k))||raw.cwd!==DEV_TASK_HOME||!Array.isArray(raw.argv)||raw.argv.length!==8)throw Error("Development scope request shape denied");
 const [marker,owner,repo,pr,sha,test,testBlob,edits]=raw.argv;
 if(marker!==DEV_TASK_MARKER||typeof owner!=="string"||typeof repo!=="string"||!(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(owner))||!(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,65}$/.test(repo))||
    typeof pr!=="string"||!(/^[1-9][0-9]{0,5}$/.test(pr))||typeof sha!=="string"||!(/^[0-9a-f]{40}$/.test(sha))||
    typeof testBlob!=="string"||!(/^[0-9a-f]{40}$/.test(testBlob))||!devTaskSafePath(test,"test")||typeof edits!=="string")throw Error("Invalid repository, PR identity, test or hash");
 const editable=edits.split(";");
 if(editable.length<1||editable.length>4||new Set(editable).size!==editable.length||editable.includes(test)||!editable.every(x=>devTaskSafePath(x,"edit")))throw Error("Invalid exact-file edit scope");
 const id=(owner+"-"+repo+"-pr"+pr).toLowerCase();
 if(id.length>100||!/^[a-z0-9][a-z0-9_.-]+$/.test(id))throw Error("Workspace label denied");
 const timeout=raw.timeout===undefined?15:raw.timeout;
 if(!Number.isInteger(timeout)||timeout<1||timeout>30)throw Error("Scope request timeout denied");
 const url="https://github.com/"+owner+"/"+repo+".git";
 const base=DEV_TASK_ROOT+"/"+id,tree=base+"/tree";
 return {owner,repo,pr,sha,test,testBlob,editable,id,url,base,tree};
}
export function devTaskCommands(s){
 const shared=s.base,testArg=s.test;
 const testCmd=testArg.endsWith(".py")?
  ["python","-I","-c","import os;os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1';import pytest;raise SystemExit(pytest.main(['"+testArg+"','-q','-p','no:cacheprovider']))"]:
  ["bun","test",testArg];
 return [
  {name:"prepare",cwd:DEV_TASK_HOME,argv:["python","-I","-S","-c",DEV_TASK_SETUP_SCRIPT,s.id],limit:30},
  {name:"toolchain",cwd:DEV_TASK_HOME,argv:["python","-I","-S","-c",DEV_TASK_TOOLCHAIN_SCRIPT],limit:20},
  {name:"clone",cwd:shared,argv:["git","-c","credential.interactive=never","-c","core.hooksPath=NUL","clone","--no-checkout","--filter=blob:none",s.url,"repo"],limit:90},
  {name:"fetch",cwd:shared,argv:["git","-c","credential.interactive=never","-C","repo","fetch","--no-tags","origin","refs/pull/"+s.pr+"/head:refs/remotes/origin/pr-"+s.pr],limit:90},
  {name:"worktree",cwd:shared,argv:["git","-c","core.hooksPath=NUL","-c","filter.lfs.required=false","-c","filter.lfs.smudge=","-C","repo","worktree","add","--detach","../tree",s.sha],limit:90},
  {name:"status",cwd:shared,argv:["git","-C","tree","status","--short","--untracked-files=normal"],limit:30},
  {name:"head",cwd:shared,argv:["git","-C","tree","rev-parse","HEAD"],limit:30},
  {name:"worktrees",cwd:shared,argv:["git","-C","repo","worktree","list","--porcelain"],limit:30},
  {name:"diff",cwd:shared,argv:["git","-C","tree","diff","--",...s.editable],limit:30},
  {name:"tests",cwd:s.tree,argv:testCmd,limit:90},
 ];
}
export function devTaskAllowedCommand(raw,scope){
 if(!raw||typeof raw!=="object"||Array.isArray(raw)||Object.keys(raw).some(k=>!["argv","cwd","timeout"].includes(k))||!Array.isArray(raw.argv))throw Error("Unexpected developer task arguments");
 const match=devTaskCommands(scope).find(x=>x.cwd===raw.cwd&&x.argv.length===raw.argv.length&&x.argv.every((v,i)=>v===raw.argv[i]));
 if(!match)throw Error("Command is outside approved project: no push, reset, clean, delete or general shell");
 const timeout=raw.timeout===undefined?match.limit:raw.timeout;
 if(!Number.isInteger(timeout)||timeout<1||timeout>match.limit)throw Error("Task command timeout exceeds approved maximum");
 return {argv:[...match.argv],cwd:match.cwd,timeout};
}
export function devTaskAllowedWrite(args,scope){
 if(!args||typeof args!=="object"||Array.isArray(args)||Object.keys(args).some(k=>!["path","content","overwrite"].includes(k))||typeof args.content!=="string"||!args.content.trim()||args.content.includes("\0")||
 Buffer.byteLength(args.content,"utf8")>DEV_TASK_MAX_BYTES||typeof args.overwrite!=="boolean")return false;
 const file=args.path?.startsWith(scope.tree+"/")?args.path.slice(scope.tree.length+1):null;
 return typeof file==="string"&&scope.editable.includes(file);
}
function devTaskScopeDigest(s){return projectDigest(DEV_TASK_POLICY+JSON.stringify(s)+DEV_TASK_GUARD_SCRIPT+DEV_TASK_FILE_GUARD_SCRIPT+DEV_TASK_TOOLCHAIN_SCRIPT)}
async function devTaskCheckRun(argv,cwd,expect){
 const r=await relay("rian_eemf_run_command",{argv,cwd,timeout:25},true);
 if(r?.result?.exit_code!==0)throw Error("Developer task workspace or Git identity check failed");
 const stdout=String(r?.result?.stdout||"").trim();
 if(expect.startsWith("RIAN_")?!stdout.includes(expect):stdout!==expect)throw Error("Developer task remote identity mismatch");
}
async function devTaskPreflight(safe,scope){
 const cmd=devTaskCommands(scope).find(x=>safe.cwd===x.cwd&&JSON.stringify(safe.argv)===JSON.stringify(x.argv));
 if(!cmd)throw Error("Not approved task command");
 if(cmd.name==="prepare")return;
 await devTaskCheckRun(["python","-I","-S","-c",DEV_TASK_GUARD_SCRIPT,scope.id],DEV_TASK_HOME,"RIAN_DEV_GUARD_OK");
 if(cmd.name==="clone"||cmd.name==="toolchain")return;
 await devTaskCheckRun(["git","-C","repo","remote","get-url","origin"],scope.base,scope.url);
 if(cmd.name==="fetch")return;
 if(cmd.name==="worktree"){
  await devTaskCheckRun(["git","-C","repo","rev-parse","refs/remotes/origin/pr-"+scope.pr],scope.base,scope.sha);
  return;
 }
 if(["status","head","diff","tests"].includes(cmd.name))
  await devTaskCheckRun(["git","-C","tree","rev-parse","HEAD"],scope.base,scope.sha);
 if(cmd.name==="tests")
  await devTaskCheckRun(["git","-C","tree","hash-object",scope.test],scope.base,scope.testBlob);
}
function devTaskMaySnapshot(clientId,path){
 for(const s of trustedSessions.values())
  if(s.profile===DEV_TASK_PROFILE&&s.clientId===clientId&&s.scope&&currentSessionState(s)==="ACTIVE"&&s.scope.editable.some(x=>path===s.scope.tree+"/"+x))return true;
 return false;
}
async function devTaskWrite(sid,args,clientId){
 const s=ownedSession(sid,clientId);
 if(s.profile!==DEV_TASK_PROFILE||currentSessionState(s)!=="ACTIVE"||s.remaining<=0||!s.scope||!devTaskAllowedWrite(args,s.scope))throw Error("Project edit not approved");
 if(s.busy)throw Error("Another task command is running");
 s.busy=true;
 try{
  if(s.sourceHash!==await trustedSourceDigest(DEV_TASK_PROFILE)||s.scopeHash!==devTaskScopeDigest(s.scope)){s.state="REVOKED";s.remaining=0;throw Error("Project grant policy changed")}
  const scope=s.scope,rel=args.path.slice(scope.tree.length+1);
  const statusCmd=devTaskCommands(scope).find(x=>x.name==="status");
  await devTaskPreflight({argv:statusCmd.argv,cwd:statusCmd.cwd},scope);
  await devTaskCheckRun(["python","-I","-S","-c",DEV_TASK_FILE_GUARD_SCRIPT,scope.id,rel],DEV_TASK_HOME,"RIAN_DEV_FILE_OK");
  const folder=args.path.slice(0,args.path.lastIndexOf("/")),basename=args.path.slice(args.path.lastIndexOf("/")+1);
  const listing=await relay("rian_eemf_list_directory",{path:folder});
  const found=listing?.result?.entries?.find(x=>x.name===basename);
  if(found&&found.type!=="file")throw Error("Target is not a plain file");
  if(Boolean(found)!==args.overwrite)throw Error("Create/overwrite mismatch");
  let before=null;
  if(args.overwrite){
   const snapshot=projectSnapshots.get(projectKey(clientId,args.path));
   if(!snapshot||snapshot.until<=now())throw Error("Read target source in chat before editing");
   const actual=await relay("rian_eemf_read_file",{path:args.path});
   before=actual?.result?.content;
   if(typeof before!=="string"||projectDigest(before)!==snapshot.hash)throw Error("Conflict: project source changed since last read");
   if(before===args.content)return sessionReply({device,profile:DEV_TASK_PROFILE,path:args.path,no_change:true,sha256:snapshot.hash,remaining_calls:s.remaining});
  }
  if(currentSessionState(s)!=="ACTIVE")throw Error("Approval expired before write");
  s.remaining--;auditTrusted("dev_task_write_started",sid,{path:rel,remaining:s.remaining});
  await relay("rian_eemf_write_file",{path:args.path,content:args.content,overwrite:args.overwrite},true);
  const result=await relay("rian_eemf_read_file",{path:args.path});
  if(result?.result?.content!==args.content)throw Error("Developer source write readback mismatch");
  projectTrackRead(clientId,args.path,args.content);
  auditTrusted("dev_task_write_verified",sid,{path:rel,remaining:s.remaining});
  return sessionReply({device,profile:DEV_TASK_PROFILE,path:args.path,write_verified:true,old_sha256:before?projectDigest(before):null,sha256:projectDigest(args.content),remaining_calls:s.remaining,diff:projectDiff(before||"",args.content)});
 }finally{s.busy=false}
}

const DEV_PROFILE="dev-version-checks-v1",DEV_CWD="Documents";
const DEV_VERSION_CMDS=["python","git","node"];
const DEV_POLICY_PIN="rian-commander|dev-version-checks-v1|cwd=Documents|python --version|git --version|node --version|no-write|2026-11-18";
const DEV_APPROVAL_SECONDS=1800,DEV_TASK_APPROVAL_SECONDS=86400,DEFAULT_APPROVAL_SECONDS=300,DEV_APPROVAL_FORM_SECONDS=600;
function trustedWorkspace(profile){return profile===DEV_TASK_PROFILE?DEV_TASK_ROOT:profile===V2_PROFILE?V2_ROOT:profile===PROJECT_PROFILE?PROJECT_DIR:profile===SMOKE_PROFILE?SMOKE_DIR:profile===DEV_PROFILE?DEV_CWD:profile===OUTLOOK_PROFILE?OUTLOOK_CWD:TRUSTED_CWD;}
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
 if(profile===DEV_TASK_PROFILE){devTaskParseScope(raw);return {argv:[...raw.argv],cwd:raw.cwd,timeout:raw.timeout===undefined?15:raw.timeout};}

 if(profile===V2_PROFILE){
  if(!raw||typeof raw!=="object"||Array.isArray(raw)||Object.keys(raw).some(k=>!["argv","cwd","timeout"].includes(k))||raw.cwd!==V2_CWD||!Array.isArray(raw.argv))throw Error("V2 project cwd/argv denied");
  const exact=(arr,expected)=>arr.length===expected.length&&arr.every((x,i)=>x===expected[i]);
  if(!exact(raw.argv,V2_BOOT)&&!exact(raw.argv,V2_RUN))throw Error("V2 permits only pinned bootstrap and safe unit tests");
  const timeout=raw.timeout===undefined?25:raw.timeout;
  if(!Number.isInteger(timeout)||timeout<1||timeout>35)throw Error("V2 test timeout denied");
  return {argv:[...raw.argv],cwd:V2_CWD,timeout};
 }

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
 for(const p of [DEV_TASK_PROFILE,V2_PROFILE,PROJECT_PROFILE,SMOKE_PROFILE,DEV_PROFILE,OUTLOOK_PROFILE,TRUSTED_PROFILE]){try{validateTrustedMailCommand(args,p);return p}catch{}}
 return null;
}
export function approvalRequestSeconds(operation,args){
 const profile=eligibleTrustProfile(operation,args);
 return profile===DEV_TASK_PROFILE?DEV_TASK_APPROVAL_SECONDS:[V2_PROFILE,PROJECT_PROFILE,SMOKE_PROFILE,DEV_PROFILE].includes(profile)?DEV_APPROVAL_SECONDS:DEFAULT_APPROVAL_SECONDS;
}
async function trustedSourceDigest(profile=TRUSTED_PROFILE){
 if(profile===DEV_TASK_PROFILE)return projectDigest(DEV_TASK_POLICY+DEV_TASK_SETUP_SCRIPT+DEV_TASK_GUARD_SCRIPT+DEV_TASK_FILE_GUARD_SCRIPT+DEV_TASK_TOOLCHAIN_SCRIPT);
 if(profile===V2_PROFILE)return v2Sha(V2_POLICY_PIN+V2_ROOT+V2_RUNNER+V2_HISTORY_INIT+JSON.stringify(V2_BOOT)+JSON.stringify(V2_RUN));
 if(profile===PROJECT_PROFILE)return projectDigest(PROJECT_PIN+PROJECT_DIR+PROJECT_FILE+PROJECT_NOTES+JSON.stringify(PROJECT_COMPILE));
 if(profile===SMOKE_PROFILE)return createHash("sha256").update(SMOKE_PIN+SMOKE_BUG+SMOKE_FIXED+SMOKE_TEST+JSON.stringify(SMOKE_BOOT)+JSON.stringify(SMOKE_RUN)).digest("hex");
 if(profile===DEV_PROFILE)return createHash("sha256").update(DEV_POLICY_PIN,"utf8").digest("hex");
 const fileResult=await relay("rian_eemf_read_file",{path:trustedScript(profile)});
 const content=fileResult?.result?.content;
 if(typeof content!=="string"||content.length<50||content.length>25000)throw Error("Trusted script unavailable");
 return createHash("sha256").update(content,"utf8").digest("hex");
}
function sessionSummary(id,session){
 return {session_id:id,device,profile:session.profile||TRUSTED_PROFILE,state:currentSessionState(session),expires_at:session.validUntil||null,remaining_calls:session.remaining,maximum_calls:TRUSTED_MAX_CALLS,workspace:session.profile===DEV_TASK_PROFILE&&session.scope?session.scope.tree:trustedWorkspace(session.profile||TRUSTED_PROFILE),task:session.profile===DEV_TASK_PROFILE&&session.scope?{repository:session.scope.owner+"/"+session.scope.repo,pr:session.scope.pr,commit:session.scope.sha,test:session.scope.test,editable:session.scope.editable}:undefined};
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
  if(Object.keys(args).some(k=>k!=="profile")||(args.profile!==undefined&&![TRUSTED_PROFILE,OUTLOOK_PROFILE,DEV_PROFILE,SMOKE_PROFILE,PROJECT_PROFILE,V2_PROFILE].includes(args.profile)))throw Error("Unexpected trusted session parameters");
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

export function classifyEemfFailure(response){
 if(!response||typeof response!=="object"||Array.isArray(response))return "INVALID_AGENT_RESULT";
 if(response.ok===true)return "NONE";
 const v=[response.error,response.message,response.reason,response.result?.error,response.result?.message];
 const d=v.map(x=>typeof x==="string"?x:typeof x?.message==="string"?x.message:typeof x?.code==="string"?x.code:"").join(" ").slice(0,3000).toLowerCase();
 if(/(commandnotfound|executable[_ -]not[_ -]found|not recognized|not_in_path|executable missing|file not found: (bun|node|python|git)|cannot find.*(bun|node|python|git))/.test(d))return "EXECUTABLE_NOT_FOUND";
 if(/(disabled|can_exec.*false|not enabled)/.test(d))return "AGENT_EXECUTION_DISABLED";
 if(/(not allowed|not permitted|blocked|denied|unauthorized|policy)/.test(d))return "AGENT_POLICY_DENIED";
 if(/(working directory|cwd|path not found|cannot find path|directory does not exist)/.test(d))return "WORKDIR_UNAVAILABLE";
 if(/(timed out|timeout|deadline exceeded)/.test(d))return "EXECUTION_TIMEOUT";
 if(/(exit code|non.?zero|process.*failed)/.test(d))return "PROCESS_FAILED";
 return "AGENT_REJECTED_UNCLASSIFIED";
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
 const v=await r.json();if(v.error)throw Error("RIAN_RELAY_PROTOCOL_REJECTED");if(v.result?.isError)throw Error("RIAN_RELAY_"+classifyEemfFailure({ok:false,error:v.result?.content?.[0]?.text}));
 let parsed;
 try{parsed=JSON.parse(v.result?.content?.[0]?.text||"{}")}catch{throw Error("Invalid relay result")}
 if(parsed.ok!==true){const category=classifyEemfFailure(parsed);if(ownerApproved)console.warn("RIAN_AGENT_REJECTED",JSON.stringify({category,device,operation:name}));throw Error("RIAN_EEMF_"+category)}
 return parsed;
}
function sessionReply(value){return {content:[{type:"text",text:JSON.stringify(value)}]}}
export function newTrustedSession(clientId,profile=TRUSTED_PROFILE){
 if(![TRUSTED_PROFILE,OUTLOOK_PROFILE,DEV_PROFILE,SMOKE_PROFILE,PROJECT_PROFILE,V2_PROFILE].includes(profile))throw Error("Unsupported trusted profile");
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
 const safe=s.profile===DEV_TASK_PROFILE?devTaskAllowedCommand(raw,s.scope):validateTrustedMailCommand(raw,s.profile||TRUSTED_PROFILE);
 s.busy=true;
 try{
  const digest=await trustedSourceDigest(s.profile||TRUSTED_PROFILE);
  if(s.sourceHash!==digest){s.state="REVOKED";s.remaining=0;throw Error("Trusted script changed; session revoked")};
  if(currentSessionState(s)!=="ACTIVE")throw Error("Trusted session no longer active");
  if(s.profile===SMOKE_PROFILE&&JSON.stringify(safe.argv)===JSON.stringify(SMOKE_RUN))await smokeVerifySources();
  if(s.profile===V2_PROFILE&&JSON.stringify(safe.argv)===JSON.stringify(V2_RUN))await v2CheckRunner();
  if(s.profile===DEV_TASK_PROFILE){if(!s.scope||s.scopeHash!==devTaskScopeDigest(s.scope))throw Error("Approved project manifest changed");await devTaskPreflight(safe,s.scope);}
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
  if(name==="rian_eemf_read_file"&&typeof val?.result?.content==="string"){
   projectTrackRead(clientId,args.path,val.result.content);
   if(devTaskMaySnapshot(clientId,args.path)&&Buffer.byteLength(val.result.content,"utf8")<=DEV_TASK_MAX_BYTES)projectSnapshots.set(projectKey(clientId,args.path),{hash:projectDigest(val.result.content),until:now()+PROJECT_SNAPSHOT_TTL});
  }
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
   if(s.clientId===clientId&&s.profile===V2_PROFILE&&currentSessionState(s)==="ACTIVE"&&v2WriteAllowed(args))
    return v2Write(sid,args,clientId);
   if(s.clientId===clientId&&s.profile===DEV_TASK_PROFILE&&currentSessionState(s)==="ACTIVE"&&s.scope&&devTaskAllowedWrite(args,s.scope))
    return devTaskWrite(sid,args,clientId);
  }
 }
 if(name==="rian_eemf_request_command"){
  const {approval_mode,...command}=args;
  if(approval_mode!=="each"){
   for(const [sid,s] of trustedSessions){
    if(s.clientId!==clientId||s.profile!==DEV_TASK_PROFILE||currentSessionState(s)!=="ACTIVE"||!s.scope)continue;
    try{devTaskAllowedCommand(command,s.scope)}catch{continue}
    return trustedDispatch("rian_eemf_run_trusted_command",{session_id:sid,...command},clientId);
   }
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
 return {content:[{type:"text",text:JSON.stringify({action_id:actionId,device,status:"PENDING_APPROVAL",preview:operation==="rian_eemf_run_command"?{argv:args.argv,cwd:args.cwd||null,timeout:args.timeout}:{path:args.path,overwrite:args.overwrite,contentLength:args.content.length},approval_url:origin+"/approve/"+actionId,expires_in_seconds:ttl,expires_at:issuedAt+ttl,note:ttl===DEV_TASK_APPROVAL_SECONDS?"No command executed. Project-scope approval request valid up to 24 hours (lost on gateway restart). Approved session starts after owner password and lasts at most 60 minutes or 60 calls.":ttl===DEV_APPROVAL_SECONDS?"No action executed. Scoped request valid 30 minutes; owner may approve a timed session.":"No action executed. General command or write approval expires in 5 minutes and requires separate owner confirmation."})}]};
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
 const proof=ticket({type:"eemf-action-approval",id,exp:now()+([DEV_TASK_PROFILE,V2_PROFILE,PROJECT_PROFILE,SMOKE_PROFILE,DEV_PROFILE].includes(profile)?DEV_APPROVAL_FORM_SECONDS:240),nonce:rand(16)});
 const label=profile===DEV_TASK_PROFILE?"선택한 GitHub 저장소·PR 고정 SHA 기반 격리 개발 프로젝트: Git clone/fetch/worktree, 지정 단위 테스트, 명시한 파일만 수정":profile===V2_PROFILE?"전용 테스트 프로젝트 상위 .py/.md 파일 최대 8개 편집, 변경 이력 저장과 내용 롤백, 검증된 계산기 단위 테스트만 실행":profile===PROJECT_PROFILE?"격리 테스트 프로젝트 calculator.py·notes.md 파일 수정(원본 해시 검증)과 Python 문법 검사만":profile===SMOKE_PROFILE?"격리 테스트 폴더의 지정된 Python 파일 2개 생성·단일 오류 수정·고정 테스트 실행":profile===DEV_PROFILE?"개발 환경 버전 확인 (Python · Git · Node.js, Documents 폴더만)":profile===OUTLOOK_PROFILE?"Outlook 로컬 메일 메타데이터 검색":profile===TRUSTED_PROFILE?"Proton 로컬 색인 상태·제목 검색":"";
 const ownerOptions=profile===DEV_TASK_PROFILE?'<option value="timed" selected>프로젝트 범위 시간 제한 승인</option>':'<option value="once" selected>이번 명령만 승인</option><option value="timed">선택한 시간 동안 같은 범위 반복 허용</option>';
 const options=profile?
  '<label for="approval_mode">승인 방식</label><select id="approval_mode" name="approval_mode">'+ownerOptions+'</select>'+
  '<p>허용 범위: '+escape(label)+'. '+escape(profile===DEV_TASK_PROFILE?"승인할 저장소, PR, 커밋, 검사 파일 및 수정 허용 파일은 아래 요청에 고정됩니다. Git fetch·worktree·상태·diff 및 지정 pytest/Bun 테스트만 자동 실행합니다. 테스트는 해당 저장소 코드를 현재 Windows 사용자 권한으로 실행하므로 신뢰 가능한 저장소만 승인하세요. Git push/reset/clean, 삭제, 패키지 설치, 운영 배포는 포함되지 않습니다.":profile===V2_PROFILE?"허용 범위는 RIAN-Commander-Smoke 상위 .py/.md 최대 8개 파일입니다. 기존 파일은 먼저 읽어야 하며 해시가 다르면 수정하지 않습니다. 이전 내용은 rian_history.json에 저장되어 되돌릴 수 있습니다. 계산기 단위 테스트는 고정된 AST 검사기와 테스트 원본 검증을 통과한 경우에만 실행합니다. 새 파일의 삭제를 통한 롤백 및 일반 터미널은 허용하지 않습니다.":profile===PROJECT_PROFILE?"승인하면 전용 폴더의 calculator.py와 notes.md를 채팅에서 수정할 수 있습니다. 반드시 먼저 파일을 읽고 해시가 일치해야 합니다. 코드를 실행하는 테스트는 허용되지 않으며 Python 문법 검사만 가능합니다. 다른 파일 및 삭제는 불가합니다.":profile===SMOKE_PROFILE?"승인하면 고정된 테스트 코드의 파일 생성·수정과 테스트 실행이 추가 암호 없이 가능합니다. 다른 폴더·명령·삭제는 허용되지 않습니다.":"해당 범위 외 명령, 파일 변경·삭제, 메일 본문 조회·동기화는 포함되지 않습니다.")+'</p>'+
  '<label for="duration_minutes">시간 제한 세션 유효시간 (분, 1~60)</label><input id="duration_minutes" name="duration_minutes" type="number" min="1" max="60" step="1" value="'+(profile===DEV_TASK_PROFILE?"60":"30")+'" required>'+
  '<p>시간 제한 방식에서만 적용됩니다. 최대 60회 실행하면 시간과 관계없이 만료됩니다.</p>':
  '<input type="hidden" name="approval_mode" value="once"><p>이 명령은 반복 허용 대상이 아니므로 이번 1회만 승인할 수 있습니다.</p>';
 return html('<h1>EEMFO3L 작업 승인</h1><p>대상 PC: DESKTOP-EEMFO3L</p><p>승인 요청 만료 시각: '+escape(new Date(item.exp*1000).toLocaleString("ko-KR",{timeZone:"Asia/Seoul"}))+' (한국시간). '+escape(profile===DEV_TASK_PROFILE?'개발 작업 범위 승인 요청은 최대 24시간 유효하지만 서버가 재시작하면 만료될 수 있습니다. 이 페이지를 연 뒤 10분 이내 승인 양식을 제출하세요. 승인된 실행 세션은 최대 60분·60회입니다.':'버전 확인 및 격리 테스트 승인 요청은 최대 30분, 일반 명령·파일 쓰기는 5분간 유효합니다.')+'</p><p>사용자가 승인 방식과 시간을 선택합니다.</p><pre style="white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1423;padding:12px">'+escape(description)+'</pre>'+(msg?'<p role="alert">'+escape(msg)+'</p>':"")+'<form method="POST" action="/action/approve"><input type="hidden" name="request" value="'+escape(proof)+'">'+options+'<label for="password">소유자 암호</label><input name="password" id="password" type="password" minlength="20" autocomplete="current-password" required><button type="submit">선택한 방식으로 승인 및 실행</button></form>',200,"same-origin");
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
   return html("<h1>제한형 세션 승인 완료</h1><p>DESKTOP-EEMFO3L "+escape(s.profile===V2_PROFILE?"전용 프로젝트 코드 패치·검증된 테스트·변경 이력 복원":s.profile===PROJECT_PROFILE?"격리 프로젝트 코드 수정 및 문법 검사":s.profile===DEV_PROFILE?"개발 환경 버전 확인":s.profile===OUTLOOK_PROFILE?"Outlook 메타데이터 검색":"Proton 색인 상태·제목 검색")+"을 "+durationMinutes+"분간 최대 60회 허용했습니다. 허용되지 않은 모든 명령은 기존대로 별도 승인이 필요합니다.</p>");
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
  if(profile===DEV_TASK_PROFILE&&mode!=="timed")return html("<h1>개발 프로젝트는 범위 지정 승인만 가능합니다.</h1>",400);
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
    const manifest=profile===DEV_TASK_PROFILE?devTaskParseScope(item.args):null;
    const s={clientId:item.clientId,profile,state:"VERIFYING",requestUntil:now()+300,validUntil:null,remaining:0,sourceHash:null,busy:false,attempts:0,scope:manifest,scopeHash:manifest?devTaskScopeDigest(manifest):null};
    trustedSessions.set(sessionId,s);
    s.sourceHash=await trustedSourceDigest(profile);
    if(s.state!=="VERIFYING")throw Error("Session was revoked");
    s.state="ACTIVE";s.validUntil=now()+durationMinutes*60;s.remaining=TRUSTED_MAX_CALLS;
    auditTrusted("activated",sessionId,{profile,duration_minutes:durationMinutes,expires_at:s.validUntil,max_calls:TRUSTED_MAX_CALLS});
    if(profile===DEV_TASK_PROFILE){
     item.status="COMPLETE";item.done=now();item.summary=JSON.stringify({ok:true,scope:s.scope,approval_session:{id:sessionId,profile,expires_at:s.validUntil,remaining_calls:s.remaining,duration_minutes:durationMinutes}}).slice(0,30000);
     return html("<h1>RIAN Commander 개발 작업 세션 승인 완료</h1><p>지정 저장소 "+escape(s.scope.owner+"/"+s.scope.repo)+" / PR "+escape(s.scope.pr)+"의 Git·테스트·파일 수정이 "+durationMinutes+"분 동안 최대 60회 허용됩니다. 현재 PC에서 명령은 실행하지 않았습니다. ChatGPT로 돌아가 연속 작업을 요청하세요.</p>");
    }
    const response=await trustedDispatch("rian_eemf_run_trusted_command",{session_id:sessionId,...item.args},item.clientId);
    const executed=JSON.parse(response.content?.[0]?.text||"{}");
    if(!executed.execution||executed.execution.ok!==true)throw Error("Initial trusted command did not complete");
    item.status="COMPLETE";item.done=now();
    item.summary=JSON.stringify({...executed.execution,approval_session:{id:sessionId,profile,expires_at:s.validUntil,remaining_calls:s.remaining,duration_minutes:durationMinutes}}).slice(0,30000);
    return html('<h1>작업 완료 · 제한형 세션 시작</h1><p>'+escape(profile===V2_PROFILE?"전용 프로젝트 파일 변경·테스트·이력 복원":profile===PROJECT_PROFILE?"전용 파일 calculator.py·notes.md 수정 및 문법 검사":profile===SMOKE_PROFILE?"전용 테스트 파일 생성·수정 및 고정 테스트 실행":"허용된 조회 명령")+'을 '+durationMinutes+'분간 최대 60회 허용합니다. 남은 횟수: '+s.remaining+'. 다른 파일이나 일반 명령은 포함되지 않습니다.</p>');
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
