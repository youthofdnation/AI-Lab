import {test, expect} from "bun:test";
import {readFileSync} from "node:fs";
process.env.RIAN_TEST_MODE="1";
const gw=await import("./gateway.ts");
const read=(file:string)=>readFileSync(new URL(file,import.meta.url),"utf8");
const gateway=read("./gateway.ts"),relay=read("./relay.ts"),policy=read("./tenant-job-policy.mjs");

test("V2 job bridge is off unless a V2 URL and a tenant-owner token are configured",()=>{
 expect(gw.v2Ready).toBe(false);
 expect(gateway).toContain('v2Key.length>=40');
 expect(gateway).toContain('/^https:\\/\\/[a-z0-9.-]+\\/v2\\/mcp$/.test(v2Url)');
 expect(gateway).toContain('env.RIAN_V2_ALLOW_LOOPBACK==="1"&&/^http:\\/\\/127\\.0\\.0\\.1:\\d+\\/v2\\/mcp$/');
});
test("V2 calls are forwarded only after the existing OAuth access-token check",()=>{
 const mcp=gateway.indexOf('if(p==="/mcp"&&(m==="GET"||m==="POST"))');
 const auth=gateway.indexOf('if(!token||token.typ!=="access"||token.aud!==resource',mcp);
 const forward=gateway.indexOf('result=await v2Rpc("tools/call"',mcp);
 expect(mcp).toBeGreaterThanOrEqual(0);
 expect(auth>mcp&&forward>auth).toBe(true);
 expect(gateway).toContain('if(v2Ready&&v2ToolAllowed(name))');
 expect(gateway).toContain('.filter(t=>v2ToolAllowed(t?.name))');
 expect(gateway).toContain('if(!bridgeReady)throw Error("Backend unavailable")');
});
test("gateway sends a client digest, never the OAuth client id or access token, to the job service",()=>{
 expect(gateway).toContain('"x-rian-client-ref":createHash("sha256").update("rian-v2-client|"+clientId).digest("hex").slice(0,32)');
 const fn=gateway.slice(gateway.indexOf("export async function v2Rpc"),gateway.indexOf("async function v2Tools"));
 expect(fn).not.toContain("authorization\":\"Bearer \"+token");
 expect(fn).toContain('redirect:"error"');
 expect(fn).toContain("AbortSignal.timeout(35000)");
});
test("no MCP tool can approve a V2 job; legacy tool list unchanged",()=>{
 expect(gateway).not.toContain('name:"rian_v2_approve');
 for(const x of ["rian_eemf_status","rian_eemf_request_command","rian_eemf_request_trusted_session","rian_eemf_action_status"])expect(gateway).toContain('name:"'+x+'"');
 expect(gateway).toContain('result={tools:[...(bridgeReady?tools:[]),...(v2Ready?await v2Tools(token.client_id).catch(()=>[]):[])]}');
});
test("general fleet and file reads cannot reach the mail cache or mailbox files",()=>{
 expect(relay).toContain('"rian-mail-v2","rian-outlook-bridge"');
 expect(relay).toContain('if(low.some(x=>/\\.(eml|mbox|msg|pst|ost)$/.test(x)))throw Error("Mail content is not available through fleet reads');
 expect(relay).toContain('".env","rian-mail-v2"];');
 expect(relay).toContain('pem|pfx|p12|key|eml|mbox|msg|pst|ost');
 expect(gateway).toContain('"ntuser.dat","rian-mail-v2"]');
 expect(gateway).toContain('/\\.(pfx|pem|key|eml|mbox|msg|pst|ost)$/');
 expect(policy).toContain("'config.json','rian-mail-v2'");
});

test("V2 mail forwarding is limited to the six fixed read-only tools",()=>{
 const decl=/const v2MailTools=new Set\(\[(.*?)\]\);/.exec(gateway);
 const predicate=/function v2ToolAllowed\(name\)\{[^\n]+\}/.exec(gateway);
 expect(decl).not.toBeNull();
 expect(predicate).not.toBeNull();
 const expected=["mail_status","mail_sync","mail_search","mail_read","mail_recent","mail_review_pending"];
 expect(JSON.parse("["+decl![1]+"]")).toEqual(expected);
 expect(predicate![0]).toBe('function v2ToolAllowed(name){return typeof name==="string"&&(/^rian_v2_[a-z_]+$/.test(name)||v2MailTools.has(name))}');
 expect(expected.some(name=>/send|delete|move|approve|shell|command/.test(name))).toBe(false);
});
