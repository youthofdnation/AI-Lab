import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
process.env.RIAN_TEST_MODE="1";
const {validateTrustedMailCommand,newTrustedSession,ownedSession,currentSessionState,trustedSessions,trustedDispatch,approvalRequestSeconds,smokeWriteAllowed,projectWriteAllowed,v2MutablePath,v2WriteAllowed,devTaskSafePath,devTaskParseScope,devTaskCommands,devTaskAllowedCommand,devTaskAllowedWrite,classifyEemfFailure,eemfFailureGuidance}=await import("./gateway.ts");
const source=readFileSync(new URL("./gateway.ts",import.meta.url),"utf8");
const cwd="Documents/RIAN-Proton-Tools";
const valid=(argv:string[],timeout=30)=>validateTrustedMailCommand({argv,cwd,timeout});
describe("Proton scoped trusted session commands",()=>{
 test("allows status read",()=>expect(valid(["python","proton_mail_query.py","status"]).argv).toEqual(["python","proton_mail_query.py","status"]));
 test("allows exact subject search",()=>expect(valid(["python","proton_mail_query.py","search","전승열"]).cwd).toBe(cwd));
 test("allows bounded --limit only",()=>expect(valid(["python","proton_mail_query.py","search","특허","--limit","20"]).argv[5]).toBe("20"));
 test("rejects full-text body reads",()=>expect(()=>valid(["python","proton_mail_query.py","search","patent","--full-text"])).toThrow());
 test("rejects private/all mail",()=>expect(()=>valid(["python","proton_mail_query.py","search","patent","--all"])).toThrow());
 test("rejects mail body read",()=>expect(()=>valid(["python","proton_mail_query.py","read","proton-abc"])).toThrow());
 test("rejects ingest/sync",()=>expect(()=>valid(["python","proton_ingest.py","--prepare"])).toThrow());
 test("rejects Python code evaluation",()=>expect(()=>valid(["python","-c","print(1)"])).toThrow());
 test("rejects PowerShell/shell",()=>expect(()=>valid(["powershell","-Command","echo hello"])).toThrow());
 test("rejects arbitrary cwd",()=>expect(()=>validateTrustedMailCommand({argv:["python","proton_mail_query.py","status"],cwd:"Documents"})).toThrow());
 test("rejects line breaks",()=>expect(()=>valid(["python","proton_mail_query.py","search","hello\nbad"])).toThrow());
 test("rejects flags in search text",()=>expect(()=>valid(["python","proton_mail_query.py","search","--all"])).toThrow());
 test("rejects oversized limit",()=>expect(()=>valid(["python","proton_mail_query.py","search","foo","--limit","99"])).toThrow());
 test("rejects too many argv",()=>expect(()=>valid(["python","proton_mail_query.py","search","hello","--limit","2","x"])).toThrow());
 test("rejects extra arguments",()=>expect(()=>validateTrustedMailCommand({argv:["python","proton_mail_query.py","status"],cwd,overwrite:true})).toThrow());
 test("rejects excessive timeout",()=>expect(()=>validateTrustedMailCommand({argv:["python","proton_mail_query.py","status"],cwd,timeout:90})).toThrow());
});
describe("trusted session authorization source checks",()=>{
 test("bound to requester OAuth client",()=>{
   expect(source).toContain("s.clientId===clientId");
   expect(source).toContain("session.clientId!==clientId");
   expect(source).toContain("token.client_id");
 });
 test("requires browser password; no agent approve tool",()=>{
   expect(source).toContain('p==="/session/activate"');
   expect(source).toContain('passwordOK(values.get("password")');
   expect(source).toContain('if(originHeader!==origin)');
   expect(source).not.toContain('name:"rian_eemf_approve_trusted_session"');
 });
 test("limits time/calls and supports immediate revocation",()=>{
   expect(source).toContain("TRUSTED_DURATION_SECONDS=1800");
   expect(source).toContain("TRUSTED_MAX_CALLS=60");
   expect(source).toContain('s.state="REVOKED";s.remaining=0');
   expect(source).toContain("s.remaining--");
   expect(source).toContain("if(s.busy)throw Error");
 });
 test("pins exact source and signs one-use relay approval each command",()=>{
   expect(source).toContain('s.sourceHash!==digest');
   expect(source).toContain('relay("rian_eemf_run_command",safe,true)');
   expect(source).toContain('headers["x-rian-eemf-approved"]');
 });
 test("write/ordinary commands still require individual approval",()=>{
   expect(source).toContain('name==="rian_eemf_request_command"');
   expect(source).toContain('name==="rian_eemf_request_write"');
   expect(source).toContain('actionQueue.set(actionId,{operation,args,clientId,status:"PENDING_APPROVAL",issuedAt,exp:issuedAt+ttl}');
 });
});

describe("real trusted session state transitions (no network, no command execution)",()=>{
 test("new session starts pending and is linked to one OAuth client",()=>{
  const result=newTrustedSession("rian.clientA");
  const payload=JSON.parse(result.content[0].text);
  expect(payload.state).toBe("PENDING_APPROVAL");
  expect(payload.maximum_calls).toBe(60);
  expect(payload.duration_after_approval_seconds).toBe(1800);
  const saved=ownedSession(payload.session_id,"rian.clientA");
  expect(saved.state).toBe("PENDING_APPROVAL");
  expect(()=>ownedSession(payload.session_id,"rian.otherClient")).toThrow("Unknown trusted session");
  saved.state="REVOKED";
 });
 test("rejects second active/pending session for the same client",()=>{
  const res=newTrustedSession("rian.clientB"),id=JSON.parse(res.content[0].text).session_id;
  expect(()=>newTrustedSession("rian.clientB")).toThrow("Existing pending or active trusted session");
  trustedSessions.get(id).state="REVOKED";
  expect(JSON.parse(newTrustedSession("rian.clientB").content[0].text).state).toBe("PENDING_APPROVAL");
 });
 test("pending session expires without approval",()=>{
  const res=newTrustedSession("rian.clientC"),id=JSON.parse(res.content[0].text).session_id,s=trustedSessions.get(id);
  expect(currentSessionState(s,s.requestUntil-1)).toBe("PENDING_APPROVAL");
  expect(currentSessionState(s,s.requestUntil)).toBe("EXPIRED");
 });
 test("active session expires at deadline and when quota runs out",()=>{
  const res=newTrustedSession("rian.clientD"),id=JSON.parse(res.content[0].text).session_id,s=trustedSessions.get(id);
  s.state="ACTIVE";s.validUntil=2000;s.remaining=2;
  expect(currentSessionState(s,1999)).toBe("ACTIVE");
  expect(currentSessionState(s,2000)).toBe("EXPIRED");
  const other=newTrustedSession("rian.clientE");
  const d=trustedSessions.get(JSON.parse(other.content[0].text).session_id);
  d.state="ACTIVE";d.validUntil=5000;d.remaining=0;
  expect(currentSessionState(d,3000)).toBe("EXPIRED");
 });
 test("immediate revocation prevents subsequent authorized commands",async()=>{
  const res=newTrustedSession("rian.clientF"),id=JSON.parse(res.content[0].text).session_id,s=trustedSessions.get(id);
  s.state="ACTIVE";s.validUntil=Math.floor(Date.now()/1000)+500;s.remaining=2;
  const revoked=JSON.parse((await trustedDispatch("rian_eemf_revoke_trusted_session",{session_id:id},"rian.clientF")).content[0].text);
  expect(revoked.state).toBe("REVOKED");
  expect(revoked.remaining_calls).toBe(0);
  await expect(trustedDispatch("rian_eemf_run_trusted_command",{session_id:id,argv:["python","proton_mail_query.py","status"],cwd:"Documents/RIAN-Proton-Tools",timeout:30},"rian.clientF")).rejects.toThrow("inactive");
 });
 test("another client cannot read, revoke or invoke the session",async()=>{
  const res=newTrustedSession("rian.clientG"),id=JSON.parse(res.content[0].text).session_id;
  await expect(trustedDispatch("rian_eemf_trusted_session_status",{session_id:id},"rian.other")).rejects.toThrow();
  await expect(trustedDispatch("rian_eemf_revoke_trusted_session",{session_id:id},"rian.other")).rejects.toThrow();
  trustedSessions.get(id).state="REVOKED";
 });
});

describe("chat-native developer environment checks (strict scope only)",()=>{
 const profile="dev-version-checks-v1",dir="Documents";
 const good=(argv:string[],timeout=15)=>validateTrustedMailCommand({argv,cwd:dir,timeout},profile);
 test.each(["python","git","node"])("allows exact %s --version",bin=>{
  expect(good([bin,"--version"]).argv).toEqual([bin,"--version"]);
  expect(good([bin,"--version"]).cwd).toBe(dir);
 });
 test("rejects arbitrary code, shell and state-changing operations",()=>{
  const denied=[
   ["python","-c","print(1)"],["git","checkout","main"],["git","status"],["git","reset","--hard"],
   ["node","-e","console.log(1)"],["powershell","-Command","dir"],["cmd","/c","dir"],
   ["Python","--version"],["python","--version","--extra"],["python","--version\n"]
  ];
  for(const argv of denied)expect(()=>good(argv)).toThrow();
 });
 test("rejects workspace changes and elevated timeouts",()=>{
  expect(()=>validateTrustedMailCommand({argv:["python","--version"],cwd:"Documents/Other",timeout:15},profile)).toThrow();
  expect(()=>validateTrustedMailCommand({argv:["python","--version"],cwd:"Documents",timeout:31},profile)).toThrow();
  expect(()=>validateTrustedMailCommand({argv:["python","--version"],cwd:"Documents",timeout:15,overwrite:true},profile)).toThrow();
 });
 test("mail profiles cannot execute the developer commands",()=>{
  expect(()=>validateTrustedMailCommand({argv:["python","--version"],cwd:dir}, "outlook-local-metadata-v1")).toThrow();
  expect(()=>validateTrustedMailCommand({argv:["python","--version"],cwd:dir}, "proton-local-readonly-v1")).toThrow();
 });
 test("new developer profile is bound to one client and revocable",async()=>{
  const request=newTrustedSession("rian.dev-test-client",profile);
  const info=JSON.parse(request.content[0].text);
  expect(info.profile).toBe(profile);
  expect(info.state).toBe("PENDING_APPROVAL");
  const own=JSON.parse((await trustedDispatch("rian_eemf_trusted_session_status",{session_id:info.session_id},"rian.dev-test-client")).content[0].text);
  expect(own.state).toBe("PENDING_APPROVAL");
  expect(own.workspace).toBe(dir);
  await expect(trustedDispatch("rian_eemf_trusted_session_status",{session_id:info.session_id},"rian.not-owner")).rejects.toThrow();
  const revoked=JSON.parse((await trustedDispatch("rian_eemf_revoke_trusted_session",{session_id:info.session_id},"rian.dev-test-client")).content[0].text);
  expect(revoked.state).toBe("REVOKED");
  await expect(trustedDispatch("rian_eemf_run_trusted_command",{session_id:info.session_id,argv:["python","--version"],cwd:dir,timeout:15},"rian.dev-test-client")).rejects.toThrow("inactive");
 });
 test("existing chat-native command tool reuses only approved profile and owner client",()=>{
  expect(source).toContain("eligibleTrustProfile");
  expect(source).toContain('if(approval_mode!=="each")');
  expect(source).toContain('s.clientId===clientId');
  expect(source).toContain('if(s.sourceHash!==digest)');
  expect(source).toContain('relay("rian_eemf_run_command",safe,true)');
 });
});

describe("approval request TTL hardening (bug: GET 200 then POST 409 7 seconds later)",()=>{
 const cmd=(argv:string[],cwd="Documents",timeout=15)=>approvalRequestSeconds("rian_eemf_run_command",{argv,cwd,timeout});
 test.each(["python","git","node"])("%s version check has thirty minute approval time",bin=>{
  expect(cmd([bin,"--version"])).toBe(1800);
 });
 test("dangerous or out of scope commands keep short 5-minute approval",()=>{
  expect(cmd(["python","-c","print(1)"])).toBe(300);
  expect(cmd(["git","status"])).toBe(300);
  expect(cmd(["powershell","-Command","whoami"])).toBe(300);
  expect(cmd(["python","--version"],"Documents/private")).toBe(300);
  expect(cmd(["python","--version"],"Documents",60)).toBe(300);
 });
 test("writes and mail searches do not inherit extended approvals",()=>{
  expect(approvalRequestSeconds("rian_eemf_write_file",{path:"Documents/test.txt",content:"demo",overwrite:false})).toBe(300);
  expect(approvalRequestSeconds("rian_eemf_run_command",{argv:["python","outlook_bridge.py","doctor"],cwd:"Documents/rian-outlook-bridge",timeout:20})).toBe(300);
 });
 test("source displays expiration and preserves signed browser form and owner approval",()=>{
  expect(source).toContain("const DEV_APPROVAL_SECONDS=1800,DEV_TASK_APPROVAL_SECONDS=86400,DEFAULT_APPROVAL_SECONDS=300,DEV_APPROVAL_FORM_SECONDS=600");
  expect(source).toContain("const ttl=approvalRequestSeconds(operation,args),issuedAt=now()");
  expect(source).toContain("exp:issuedAt+ttl");
  expect(source).toContain("expires_at:issuedAt+ttl");
  expect(source).toContain("승인 요청 만료 시각");
  expect(source).toContain('const proof=ticket({type:"eemf-action-approval"');
  expect(source).toContain('passwordOK(f.get("password")');
 });
});

describe("chat-native isolated developer smoke project — one user-approved scope",()=>{
 const profile="dev-sandbox-smoke-v1",cwd="Documents",root="Documents/RIAN-Commander-Smoke";
 const boot=["python","-I","-S","-c","from pathlib import Path; Path('RIAN-Commander-Smoke').mkdir(exist_ok=True); print('RIAN_SMOKE_READY')"];
 const run=["python","-I","-S","-m","unittest","discover","-s","RIAN-Commander-Smoke","-p","test_calculator.py","-v"];
 const bug="def total_with_tax(subtotal, tax_rate):\n    if subtotal < 0 or tax_rate < 0:\n        raise ValueError('negative inputs')\n    return subtotal - subtotal * tax_rate\n";
 const fixed="def total_with_tax(subtotal, tax_rate):\n    if subtotal < 0 or tax_rate < 0:\n        raise ValueError('negative inputs')\n    return subtotal + (subtotal * tax_rate)\n";
 const tests="import unittest\nfrom calculator import total_with_tax\n\nclass TaxTests(unittest.TestCase):\n    def test_tax_10(self):\n        self.assertEqual(total_with_tax(100, .1), 110)\n    def test_tax_25(self):\n        self.assertEqual(total_with_tax(80, .25), 100)\n    def test_zero(self):\n        self.assertEqual(total_with_tax(100, 0), 100)\n    def test_negative(self):\n        with self.assertRaises(ValueError):\n            total_with_tax(-1, .1)\n";
 test("allow only exact bootstrap and unittest commands",()=>{
  for(const argv of [boot,run]){
   expect(validateTrustedMailCommand({argv,cwd,timeout:25},profile).argv).toEqual(argv);
   expect(approvalRequestSeconds("rian_eemf_run_command",{argv,cwd,timeout:25})).toBe(1800);
  }
 });
 test("deny direct shell, arbitrary python, changed script, altered cwd and other tools",()=>{
  const invalid=[["powershell","-Command","whoami"],["python","-c","print(1)"],
   ["python","-I","-S","-c","import os; os.system('whoami')"],["cmd","/c","dir"],["git","reset","--hard"]];
  for(const argv of invalid)expect(()=>validateTrustedMailCommand({argv,cwd,timeout:25},profile)).toThrow();
  for(const argv of [boot,run]){
   expect(()=>validateTrustedMailCommand({argv,cwd:"Documents/Other",timeout:25},profile)).toThrow();
   expect(()=>validateTrustedMailCommand({argv,cwd,timeout:45},profile)).toThrow();
  }
 });
 test("smoke file writes are exact-content and exact-path only",()=>{
  expect(smokeWriteAllowed({path:root+"/calculator.py",content:bug,overwrite:false})).toBe(true);
  expect(smokeWriteAllowed({path:root+"/calculator.py",content:fixed,overwrite:true})).toBe(true);
  expect(smokeWriteAllowed({path:root+"/test_calculator.py",content:tests,overwrite:false})).toBe(true);
  expect(smokeWriteAllowed({path:root+"/calculator.py",content:fixed,overwrite:false})).toBe(false);
  expect(smokeWriteAllowed({path:root+"/test_calculator.py",content:tests,overwrite:true})).toBe(false);
  expect(smokeWriteAllowed({path:"Documents/real-work.py",content:bug,overwrite:false})).toBe(false);
  expect(smokeWriteAllowed({path:root+"/calculator.py",content:"import os\nos.system('whoami')\n",overwrite:true})).toBe(false);
 });
 test("sandbox profile has per-OAuth-client owned session and can be revoked",async()=>{
  const reply=newTrustedSession("rian.dev-smoke-test",profile);
  const claim=JSON.parse(reply.content[0].text);
  expect(claim.profile).toBe(profile);
  expect(claim.state).toBe("PENDING_APPROVAL");
  expect(()=>ownedSession(claim.session_id,"rian.not-owner")).toThrow();
  expect(ownedSession(claim.session_id,"rian.dev-smoke-test").profile).toBe(profile);
  const revoked=JSON.parse((await trustedDispatch("rian_eemf_revoke_trusted_session",{session_id:claim.session_id},"rian.dev-smoke-test")).content[0].text);
  expect(revoked.state).toBe("REVOKED");
 });
 test("exact-file write path and test runner are source-verified and require existing owner approval",()=>{
  expect(source).toContain("async function smokeScopedWrite");
  expect(source).toContain("s.clientId===clientId");
  expect(source).toContain('smokeWriteAllowed(args)');
  expect(source).toContain('if(s.sourceHash!==await trustedSourceDigest(SMOKE_PROFILE))');
  expect(source).toContain("Sandbox policy changed; approval revoked");
  expect(source).toContain("Overwrite refused: calculator.py differs from known buggy baseline");
  expect(source).toContain("File write verification mismatch");
  expect(source).toContain("await smokeVerifySources()");
  expect(source).toContain('passwordOK(f.get("password")');
  expect(source).toContain('relay("rian_eemf_write_file",args,true)');
 });
});

describe("generic scratch edits with CAS and bounded syntax-only execution",()=>{
 const profile="dev-workspace-edit-v1",cwd="Documents",root="Documents/RIAN-Commander-Smoke";
 const compile=["python","-I","-S","-m","py_compile","RIAN-Commander-Smoke/calculator.py"];
 test("approves only the exact safe syntax compiler",()=>{
  expect(validateTrustedMailCommand({argv:compile,cwd,timeout:20},profile).argv).toEqual(compile);
  expect(approvalRequestSeconds("rian_eemf_run_command",{argv:compile,cwd,timeout:20})).toBe(1800);
 });
 test("rejects arbitrary Python, shell, test execution and altered working folder",()=>{
  const bad=[["python","-c","print(1)"],["python","-m","unittest","discover"],
    ["powershell","-Command","whoami"],["python","-I","-S","-m","py_compile","../private.py"],
    ["cmd","/c","dir"],["python","-I","-S","-m","pip","install","package"]];
  for(const argv of bad)expect(()=>validateTrustedMailCommand({argv,cwd,timeout:20},profile)).toThrow();
  expect(()=>validateTrustedMailCommand({argv:compile,cwd:root,timeout:20},profile)).toThrow();
  expect(()=>validateTrustedMailCommand({argv:compile,cwd,timeout:50},profile)).toThrow();
 });
 test("accepts dynamic content in only two pinned scratch files",()=>{
  const src="def total_with_tax(subtotal, rate):\n    return subtotal * (1 + rate)\n";
  expect(projectWriteAllowed({path:root+"/calculator.py",content:src,overwrite:true})).toBe(true);
  expect(projectWriteAllowed({path:root+"/notes.md",content:"## Patch notes\n",overwrite:false})).toBe(true);
  expect(projectWriteAllowed({path:root+"/notes.md",content:"## Updated notes\n",overwrite:true})).toBe(true);
  for(const path of [root+"/test_calculator.py",root+"/config.json","Documents/other.py",root+"/calculator.py/../notes.md"])
    expect(projectWriteAllowed({path,content:src,overwrite:true})).toBe(false);
  expect(projectWriteAllowed({path:root+"/calculator.py",content:src,overwrite:false})).toBe(false);
  expect(projectWriteAllowed({path:root+"/calculator.py",content:"",overwrite:true})).toBe(false);
  expect(projectWriteAllowed({path:root+"/calculator.py",content:"a".repeat(5001),overwrite:true})).toBe(false);
  expect(projectWriteAllowed({path:root+"/calculator.py",content:src,overwrite:true,run:true})).toBe(false);
 });
 test("per-client owner-approved grant and explicit revoke remain mandatory",async()=>{
  const out=newTrustedSession("rian.workspace.alpha",profile),value=JSON.parse(out.content[0].text);
  expect(value.profile).toBe(profile);
  expect(value.state).toBe("PENDING_APPROVAL");
  expect(value.workspace).toBeUndefined();
  expect(()=>ownedSession(value.session_id,"rian.workspace.beta")).toThrow();
  const status=JSON.parse((await trustedDispatch("rian_eemf_trusted_session_status",{session_id:value.session_id},"rian.workspace.alpha")).content[0].text);
  expect(status.workspace).toBe(root);
  const revoked=JSON.parse((await trustedDispatch("rian_eemf_revoke_trusted_session",{session_id:value.session_id},"rian.workspace.alpha")).content[0].text);
  expect(revoked.state).toBe("REVOKED");
 });
 test("CAS preflight, owner proof and file readback enforced in source",()=>{
  expect(source).toContain("projectTrackRead(clientId,args.path,val.result.content)");
  expect(source).toContain("projectKey(clientId,args.path)");
  expect(source).toContain("snap.until<=now()");
  expect(source).toContain("projectDigest(previous)!==snap.hash");
  expect(source).toContain("CAS conflict: file modified since last read; refresh first");
  expect(source).toContain("Write verification failed");
  expect(source).toContain("grant.remaining--");
  expect(source).toContain('if(!a||a.exp<now()||a.clientId!==clientId)');
  expect(source).toContain('passwordOK(f.get("password")');
  expect(source).toContain('relay("rian_eemf_write_file",{path:args.path,content:args.content,overwrite:args.overwrite},true)');
 });
});

describe("V2 project folder, pinned tests and rollback policies",()=>{
 const profile="dev-project-history-v2",cwd="Documents",root="Documents/RIAN-Commander-Smoke";
 const boot=["python","-I","-S","-c","print('RIAN_PROJECT_V2_READY')"];
 const runner=["python","-I","-S","RIAN-Commander-Smoke/_rian_runner.py"];
 const good=(argv:string[],dir=cwd,timeout=25)=>validateTrustedMailCommand({argv,cwd:dir,timeout},profile);
 test("permits pinned profile bootstrap, pinned test runner and owner-selected duration",()=>{
  for(const cmd of [boot,runner]){
   expect(good(cmd).argv).toEqual(cmd);
   expect(approvalRequestSeconds("rian_eemf_run_command",{argv:cmd,cwd,timeout:25})).toBe(1800);
  }
 });
 test("denies arbitrary shell, raw unittest, Python eval, other cwd and timeout abuse",()=>{
  const bad=[["powershell","-Command","whoami"],["cmd","/c","dir"],["python","-c","print(1)"],
    ["python","-m","unittest","discover"],["python","-I","-S","-m","pytest"],["git","reset","--hard"]];
  for(const cmd of bad)expect(()=>good(cmd)).toThrow();
  expect(()=>good(runner,"Documents/private")).toThrow();
  expect(()=>good(runner,cwd,36)).toThrow();
 });
 test("allowlisted flat .py/.md project files, rejecting tests, helpers and traversal",()=>{
  for(const name of ["calculator.py","notes.md","helper.py","guide.md"]){
   expect(v2MutablePath(root+"/"+name)).toBe(true);
   expect(v2WriteAllowed({path:root+"/"+name,content:"some content\n",overwrite:true})).toBe(true);
  }
  for(const path of [root+"/test_calculator.py",root+"/_rian_runner.py",root+"/nested/evil.py",
      root+"/../secret.py","Documents/elsewhere.py",root+"/.env",root+"/other.json",root+"/a.PY"]){
   expect(v2MutablePath(path)).toBe(false);
  }
 });
 test("test runner and history initialization are exact-content and create-only",()=>{
  const runnerFile=root+"/_rian_runner.py",ledgerFile=root+"/rian_history.json";
  const fixture='{"version":1,"entries":[]}';
  expect(v2WriteAllowed({path:ledgerFile,content:fixture,overwrite:false})).toBe(true);
  expect(v2WriteAllowed({path:ledgerFile,content:fixture,overwrite:true})).toBe(false);
  expect(v2WriteAllowed({path:runnerFile,content:"import os",overwrite:false})).toBe(false);
  expect(v2WriteAllowed({path:root+"/calculator.py",content:"a".repeat(5001),overwrite:true})).toBe(false);
  expect(v2WriteAllowed({path:root+"/notes.md",content:" ",overwrite:false})).toBe(false);
  expect(v2WriteAllowed({path:root+"/notes.md",content:"hello",overwrite:false,delete:true})).toBe(false);
 });
 test("session is tied to OAuth client and can be immediately revoked",async()=>{
  const request=newTrustedSession("rian.v2-test",profile),payload=JSON.parse(request.content[0].text);
  expect(payload.profile).toBe(profile);
  expect(payload.state).toBe("PENDING_APPROVAL");
  expect(()=>ownedSession(payload.session_id,"rian.other")).toThrow();
  const status=JSON.parse((await trustedDispatch("rian_eemf_trusted_session_status",{session_id:payload.session_id},"rian.v2-test")).content[0].text);
  expect(status.workspace).toBe(root);
  const revoked=JSON.parse((await trustedDispatch("rian_eemf_revoke_trusted_session",{session_id:payload.session_id},"rian.v2-test")).content[0].text);
  expect(revoked.state).toBe("REVOKED");
 });
 test("source stores history on the PC before overwrite and guards against stale sources",()=>{
  for(const rule of [
   'const V2_HISTORY=V2_ROOT+"/rian_history.json"',
   'const V2_RUNNER=',
   'async function v2RecoverLedger',
   'snapshot.until<=now()',
   'CAS conflict: file changed after last read',
   'log.state="COMPLETE"',
   'await v2SaveLedger(ledger)',
   'Source write readback differs from requested content',
   'Project policy changed; session revoked',
   'async function v2CheckRunner',
   'Pinned unit test runner or fixture changed',
   'v2MutablePath(path)',
   's.clientId===clientId',
   'passwordOK(f.get("password")',
  ])expect(source).toContain(rule);
  expect(source).toContain('relay("rian_eemf_write_file",{path:args.path,content:args.content,overwrite:args.overwrite},true)');
 });
});

describe("generic owner-approved development worktree sessions (no project-specific hardcoding)",()=>{
 const intent={
  argv:["RIAN_DEV_SCOPE_V1","testowner","sample-repo","12","a".repeat(40),
     "src/controller.test.ts","b".repeat(40),"src/controller.ts;docs/developer.md"],
  cwd:"Documents",timeout:20
 };
 const config=devTaskParseScope(intent);
 const valid=(x:unknown)=>{try{devTaskParseScope(x);return true}catch{return false}};
 test("manifest binds owner, repository, PR, commit, test file and precise edit paths",()=>{
  expect(config.owner).toBe("testowner");
  expect(config.repo).toBe("sample-repo");
  expect(config.pr).toBe("12");
  expect(config.sha).toBe("a".repeat(40));
  expect(config.testBlob).toBe("b".repeat(40));
  expect(config.editable).toEqual(["src/controller.ts","docs/developer.md"]);
  expect(config.base).toBe("Documents/RIAN-Commander-Dev/testowner-sample-repo-pr12");
  expect(config.url).toBe("https://github.com/testowner/sample-repo.git");
  expect(config.tree).toBe(config.base+"/tree");
 });
 test("rejects unreviewed scope mutations and path traversal",()=>{
  const variants=[(x:any)=>x.argv[0]="python",
    (x:any)=>x.cwd="Documents/private",(x:any)=>x.argv[1]="owner;echo hacked",
    (x:any)=>x.argv[2]="../other",(x:any)=>x.argv[3]="0",
    (x:any)=>x.argv[4]="incorrect-sha",(x:any)=>x.argv[5]="build/output.test.ts",
    (x:any)=>x.argv[5]="tests/../test_bad.py",
    (x:any)=>x.argv[6]="badblob",(x:any)=>x.argv[7]="src/file.ts;src/file.ts",
    (x:any)=>x.argv[7]="tests/test_bad.py",
    (x:any)=>x.argv[7]=".github/workflows/ci.yml",
    (x:any)=>x.argv[7]="src/controller.test.ts",
    (x:any)=>x.timeout=31,(x:any)=>x.extra=true];
  for(const change of variants){const item=structuredClone(intent);change(item);expect(valid(item)).toBe(false);}
 });
 test("supports pinned Python or Bun tests, forbids hidden and escaped files",()=>{
  expect(devTaskSafePath("rian-commander/eemf-operator/trusted-session.test.ts","test")).toBe(true);
  expect(devTaskSafePath("tests/test_contract.py","test")).toBe(true);
  expect(devTaskSafePath("nested/tests/test_contract.py","test")).toBe(true);
  expect(devTaskSafePath("src/controller.test.ts","edit")).toBe(true);
  for(const unsafe of ["tests/../evil.py","src/.env","src/.git/config",
      "src/../../password.py","src/test_contract.py","src/node_modules/pkg.ts",
      "src/foo/config.sh"])
   expect(devTaskSafePath(unsafe,"edit")).toBe(false);
 });
 test("permits only the generated exact Git clone/fetch/worktree/status/diff/test commands",()=>{
  const commands=devTaskCommands(config);
  expect(commands.map(x=>x.name)).toEqual(["prepare","toolchain","clone","fetch","worktree","status","head","worktrees","diff","tests"]);
  for(const command of commands){
   expect(devTaskAllowedCommand({argv:command.argv,cwd:command.cwd,timeout:Math.min(command.limit,25)},config).argv).toEqual(command.argv);
   expect(command.limit).toBeGreaterThanOrEqual(20);
  }
  const probe=commands.find(x=>x.name==="toolchain")!;
  expect(probe.cwd).toBe("Documents");
  expect(probe.argv.slice(0,4)).toEqual(["python","-I","-S","-c"]);
  expect(probe.argv[4]).toContain("RIAN_TOOLCHAIN_V1");
  expect(probe.argv[4]).toContain("shutil.which");
  expect(probe.argv[4]).not.toContain("subprocess");
  expect(probe.argv[4]).not.toContain("os.system");
  expect(commands.find(x=>x.name==="clone")!.argv).toContain("credential.interactive=never");
  expect(commands.find(x=>x.name==="worktree")!.argv).toContain("core.hooksPath=NUL");
  expect(commands.find(x=>x.name==="tests")!.argv).toContain("src/controller.test.ts");
 });
 test("denies push, reset, clean, shell, package install and unapproved worktree removal",()=>{
  const invalid=[
   ["git","push","origin","main"],["git","reset","--hard"],["git","clean","-fd"],
   ["git","worktree","remove","../tree"],["git","clone","https://attacker.example/evil","repo"],
   ["powershell","-Command","whoami"],["cmd","/c","dir"],
   ["python","-c","import os;os.system('whoami')"],["npm","install"],["pip","install","x"]
  ];
  for(const argv of invalid)expect(()=>devTaskAllowedCommand({argv,cwd:config.base,timeout:25},config)).toThrow();
  expect(()=>devTaskAllowedCommand({argv:devTaskCommands(config)[2].argv,cwd:"Documents/other",timeout:25},config)).toThrow();
  expect(()=>devTaskAllowedCommand({argv:devTaskCommands(config).at(-1)!.argv,cwd:config.tree,timeout:91},config)).toThrow();
 });
 test("project source writes are limited to user-reviewed exact paths and 11.5k bytes",()=>{
  expect(devTaskAllowedWrite({path:config.tree+"/src/controller.ts",content:"export const x=1;",overwrite:true},config)).toBe(true);
  expect(devTaskAllowedWrite({path:config.tree+"/docs/developer.md",content:"# Notes",overwrite:false},config)).toBe(true);
  for(const x of [
   {path:config.tree+"/src/controller.test.ts",content:"x",overwrite:true},
   {path:config.tree+"/src/../hidden.ts",content:"x",overwrite:true},
   {path:config.tree+"/src/controller.ts",content:"a".repeat(11501),overwrite:true},
   {path:config.tree+"/src/controller.ts",content:" ",overwrite:true},
   {path:config.tree+"/src/controller.ts",content:"x",overwrite:true,delete:true}
  ])expect(devTaskAllowedWrite(x,config)).toBe(false);
 });
 test("owner-signed time grant is required, never relay the synthetic manifest as a PC command",()=>{
  expect(source).toContain('if(profile===DEV_TASK_PROFILE&&mode!=="timed")');
  expect(source).toContain('const manifest=profile===DEV_TASK_PROFILE?devTaskParseScope(item.args):null;');
  expect(source).toContain('scopeHash:manifest?devTaskScopeDigest(manifest):null');
  expect(source).toContain('if(profile===DEV_TASK_PROFILE){');
  expect(source).toContain('현재 PC에서 명령은 실행하지 않았습니다.');
  expect(source).toContain('passwordOK(f.get("password")');
  expect(source).toContain('if(s.profile===DEV_TASK_PROFILE){if(!s.scope||s.scopeHash!==devTaskScopeDigest(s.scope))');
  expect(source).toContain('s.clientId===clientId');
  expect(approvalRequestSeconds("rian_eemf_run_command",intent)).toBe(86400);
  expect(()=>newTrustedSession("rian.client", "dev-task-scope-v1")).toThrow();
  expect(source).toContain("DEV_TASK_APPROVAL_SECONDS=86400");
  expect(source).toContain("DEV_APPROVAL_FORM_SECONDS=600");
  expect(source).toContain("TRUSTED_MAX_DURATION_SECONDS=3600");
  expect(source).toContain("프로젝트 범위 시간 제한 승인");
 });
 test("remote Git identity, test fixture pin and canonical path checks are present",()=>{
  for(const snippet of [
   "async function devTaskPreflight(safe,scope)",
   "DEV_TASK_GUARD_SCRIPT",
   "DEV_TASK_FILE_GUARD_SCRIPT",
   '["git","-C","repo","remote","get-url","origin"]',
   '["git","-C","repo","rev-parse","refs/remotes/origin/pr-"+scope.pr]',
   '["git","-C","tree","rev-parse","HEAD"]',
   '["git","-C","tree","hash-object",scope.test]',
   "Conflict: project source changed since last read",
   "Developer source write readback mismatch",
   "await devTaskPreflight(safe,s.scope)",
   'if(devTaskMaySnapshot(clientId,args.path)',
  ])expect(source).toContain(snippet);
  expect(source).not.toContain('dev-salpion-pr16-v1');
 });
});


describe("Outlook failure root-cause classification and safe recovery",()=>{
 test("28-second legacy relay pending is NOT an agent rejection",()=>{
  expect(classifyEemfFailure({ok:false,error:"Job pending 12345678-1234-1234-1234-123456789abc"})).toBe("RELAY_JOB_PENDING_UNCONFIRMED");
  expect(classifyEemfFailure({ok:false,error:"Job expired"})).toBe("RELAY_JOB_EXPIRED_UNCONFIRMED");
  expect(classifyEemfFailure({ok:false,error:"Queue full"})).toBe("RELAY_QUEUE_CAPACITY");
  expect(classifyEemfFailure({ok:false,error:"Device offline: DESKTOP-EEMFO3L"})).toBe("DEVICE_OFFLINE");
 });
 test("real agent policy and executable errors remain distinct",()=>{
  expect(classifyEemfFailure({ok:false,error:{code:"AGENT_POLICY_DENIED",message:"redacted"}})).toBe("AGENT_POLICY_DENIED");
  expect(classifyEemfFailure({ok:false,reason_code:"EXECUTABLE_NOT_FOUND"})).toBe("EXECUTABLE_NOT_FOUND");
  expect(classifyEemfFailure({ok:false,error:"socket hang up"})).toBe("TRANSPORT_FAILURE");
  expect(classifyEemfFailure({ok:false,error:"very-private-mail-subject"})).toBe("AGENT_REJECTED_UNCLASSIFIED");
 });
 test("pending/expired uncertainty has actionable guidance, never instructs blind retry",()=>{
  expect(eemfFailureGuidance("RELAY_JOB_PENDING_UNCONFIRMED")).toContain("재전송하지");
  expect(eemfFailureGuidance("RELAY_JOB_EXPIRED_UNCONFIRMED")).toContain("중복 실행 전");
  expect(eemfFailureGuidance("AGENT_POLICY_DENIED")).toContain("허용");
  expect(eemfFailureGuidance("AGENT_REJECTED_UNCLASSIFIED")).not.toContain("원격 실행을 허용합니다");
  expect(source).toContain('const match=/^RIAN_(?:RELAY|EEMF)_([A-Z_]+)$/.exec(failure)');
 });
 test("Outlook trusted metadata policy still refuses sync and body access",()=>{
  const cwd="Documents/rian-outlook-bridge",opts=(argv:string[])=>({argv,cwd,timeout:30});
  expect(validateTrustedMailCommand(opts(["python","outlook_bridge.py","doctor"]),"outlook-local-metadata-v1").argv[2]).toBe("doctor");
  expect(validateTrustedMailCommand(opts(["python","outlook_bridge.py","search","이재철","--limit","10"]),"outlook-local-metadata-v1").argv[2]).toBe("search");
  expect(()=>validateTrustedMailCommand(opts(["python","outlook_bridge.py","sync","--days","14","--max-messages","1000"]),"outlook-local-metadata-v1")).toThrow();
  expect(()=>validateTrustedMailCommand(opts(["python","outlook_bridge.py","read","b6df3aa45a1dd1b8b6f3"]),"outlook-local-metadata-v1")).toThrow();
 });
});

describe("EEMFO3L agent rejection diagnostics",()=>{
 test("distinguishes common missing-executable messages without echoing raw paths",()=>{
  for(const raw of [
   {ok:false,error:"bun.exe : The term 'bun' is not recognized as the name of a cmdlet"},
   {ok:false,error:{message:"CommandNotFoundException: bun"}},
   {ok:false,reason:"Executable missing: bun"}
  ])expect(classifyEemfFailure(raw)).toBe("EXECUTABLE_NOT_FOUND");
 });
 test("recognizes permission, directory and timeout failure categories",()=>{
  expect(classifyEemfFailure({ok:false,error:"Not permitted by agent policy"})).toBe("AGENT_POLICY_DENIED");
  expect(classifyEemfFailure({ok:false,error:"can_exec is not enabled"})).toBe("AGENT_EXECUTION_DISABLED");
  expect(classifyEemfFailure({ok:false,error:"Working directory does not exist"})).toBe("WORKDIR_UNAVAILABLE");
  expect(classifyEemfFailure({ok:false,error:"Job timed out"})).toBe("EXECUTION_TIMEOUT");
  expect(classifyEemfFailure({ok:false,error:"Process exited with exit code 1"})).toBe("PROCESS_FAILED");
 });
 test("never prints attacker-controlled error details or treats non-zero code as agent rejection",()=>{
  expect(classifyEemfFailure({ok:true,result:{exit_code:1}})).toBe("NONE");
  expect(classifyEemfFailure(null)).toBe("INVALID_AGENT_RESULT");
  expect(classifyEemfFailure({ok:false,error:"secret-token-12345"})).toBe("AGENT_REJECTED_UNCLASSIFIED");
  expect(source).toContain('throw Error("RIAN_EEMF_"+category)');
  expect(source).toContain('throw Error("RIAN_RELAY_"+classifyEemfFailure');
  expect(source).not.toContain('throw Error("EEMFO3L agent rejected the operation")');
  expect(source).not.toContain('console.warn("RIAN_AGENT_REJECTED",parsed)');
 });
 test("toolchain probe is pinned to owner-reviewed manifest and cannot become arbitrary shell",()=>{
  expect(source).toContain("DEV_TASK_TOOLCHAIN_SCRIPT");
  expect(source).toContain('if(cmd.name==="clone"||cmd.name==="toolchain")return;');
  expect(source).toContain("DEV_TASK_POLICY+JSON.stringify(s)+DEV_TASK_GUARD_SCRIPT+DEV_TASK_FILE_GUARD_SCRIPT+DEV_TASK_TOOLCHAIN_SCRIPT");
  expect(source).toContain("DEV_TASK_POLICY+DEV_TASK_SETUP_SCRIPT+DEV_TASK_GUARD_SCRIPT+DEV_TASK_FILE_GUARD_SCRIPT+DEV_TASK_TOOLCHAIN_SCRIPT");
  const scope=devTaskParseScope({cwd:"Documents",argv:["RIAN_DEV_SCOPE_V1","testowner","repo","3","a".repeat(40),"tests/test_check.py","b".repeat(40),"src/check.py"],timeout:15});
  const probe=devTaskCommands(scope).find(x=>x.name==="toolchain")!;
  expect(devTaskAllowedCommand({cwd:probe.cwd,argv:probe.argv,timeout:20},scope).argv).toEqual(probe.argv);
  expect(()=>devTaskAllowedCommand({cwd:probe.cwd,argv:["python","-c","import os;os.system('whoami')"],timeout:20},scope)).toThrow();
  expect(()=>devTaskAllowedCommand({cwd:"Documents/private",argv:probe.argv,timeout:20},scope)).toThrow();
 });
});
