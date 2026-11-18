import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
process.env.RIAN_TEST_MODE="1";
const {validateTrustedMailCommand,newTrustedSession,ownedSession,currentSessionState,trustedSessions,trustedDispatch,approvalRequestSeconds,smokeWriteAllowed}=await import("./gateway.ts");
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
