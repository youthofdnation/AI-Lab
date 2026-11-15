import {test,expect} from "bun:test";
import {readFileSync} from "node:fs";
const c=readFileSync(new URL("./operator-gateway.ts",import.meta.url),"utf8");
test("separate MCP exposes request and status only, no approval callable tool",()=>{
  expect(c).toContain('name:"rian_d23_request_audit"');
  expect(c).toContain('name:"rian_d23_job_status"');
  expect(c).toContain('name:"rian_d23_read_result"');
  expect(c).not.toContain('name:"rian_d23_approve"');
  expect(c).not.toContain('name:"rian_run_command"');
  expect(c).not.toContain('name:"rian_write_file"');
});
test("requires distinct OAuth resource and limited d23:request scope",()=>{
  expect(c).toContain('scope:"d23:request"');
  expect(c).toContain('scopes_supported:["d23:request"');
  expect(c).not.toContain('fleet:read');
  expect(c).toContain('rian-d23-operator-v1');
});
test("approval cannot be obtained from an MCP tool call",()=>{
  const toolRegion=c.slice(c.indexOf('const tools=['),c.indexOf('function safeArgs('));
  expect(toolRegion).not.toContain('rian_d23_approve');
  const agentDispatch=c.slice(c.indexOf('async function sendBackend('),c.indexOf('function loginPage('));
  expect(agentDispatch).not.toContain('/v1/d23/approve');
  expect(agentDispatch).not.toContain('approvalKey');
  const approvalRegion=c.slice(c.indexOf('if(p==="/d23/approve"'),c.indexOf('if(p==="/oauth/register"'));
  expect(approvalRegion).toContain('passwordOK');
  expect(approvalRegion).toContain('job.state!=="PENDING_APPROVAL"');
  expect(approvalRegion).toContain('brokerFetch("/v1/d23/approve"');
});
test("rejects arbitrary device, arbitrary tools, and query arguments",()=>{
  expect(c).toContain('const device="DESKTOP-1QGT8D6"');
  expect(c).toContain('const task="D23_AUDIT_READONLY_V1"');
  expect(c).toContain('function safeArgs(name,a)');
  expect(c).toContain('Object.keys(a).length!==0');
  expect(c).toContain('Object.keys(a).length!==1');
});
test("readback checks completion, filename, and result structure",()=>{
  expect(c).toContain('if(j.state!=="COMPLETE")');
  expect(c).toContain('if(remote.ok!==true');
  expect(c).toContain('parsed.device!==device');
  expect(c).toContain('name:"rian_fleet_read_file"');
});
