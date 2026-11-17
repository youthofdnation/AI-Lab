import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
process.env.RIAN_TEST_MODE="1";
const {validateTrustedMailCommand}=await import("./gateway.ts");
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
   expect(source).toContain('actionQueue.set(actionId,{operation,args,status:"PENDING_APPROVAL"');
 });
});
