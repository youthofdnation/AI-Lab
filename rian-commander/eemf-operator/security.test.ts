import {test, expect} from "bun:test";
import {readFileSync} from "node:fs";
const read=(file:string)=>readFileSync(new URL(file,import.meta.url),"utf8");
const relay=read("./relay.ts"),gateway=read("./gateway.ts"),optin=read("./enable-eemf-owner.ps1");

test("EEMF relay requires separate credential and cannot be used as global admin",()=>{
 expect(relay).toContain('const EEMF_DEVICE="DESKTOP-EEMFO3L"');
 expect(relay).toContain('RIAN_EEMF_GATEWAY_TOKEN');
 expect(relay).toContain('EEMF_TOKEN.length>=48');
 expect(relay).toContain('if(!isEEMFGateway(req))return error("Unauthorized",401)');
 expect(relay).toContain('if(Object.hasOwn(raw,"device"))throw Error("Device override denied")');
 expect(relay).toContain('if(p==="/mcp/eemf-owner"&&method==="POST")');
});
test("legacy fleet read-only endpoints remain identical and exposed",()=>{
 for(const x of ['/mcp/gateway-readonly','/mcp/fleet-readonly','/mcp/readonly-1q'])
  expect(relay).toContain(x);
 expect(relay).toContain('if(p==="/mcp/gateway-readonly"&&method==="POST")return await mcpFleetGateway(r)');
});
test("EEMF request commands require browser-only explicit approval",()=>{
 for(const x of ["rian_eemf_request_command","rian_eemf_request_write","rian_eemf_action_status","rian_eemf_read_file"])
   expect(gateway).toContain('name:"'+x+'"');
 expect(gateway).toContain('item.status="RUNNING"');
 expect(gateway).toContain('passwordOK(f.get("password")');
 expect(gateway).toContain('if(!item||item.exp<now()||item.status!=="PENDING_APPROVAL")');
 expect(gateway).toContain('manual_approval_required:true');
 expect(gateway).not.toContain('name:"rian_run_command"');
});
test("separate OAuth scope and no root/admin broad relay token",()=>{
 expect(gateway).toContain('role:"eemf-owner"');
 expect(gateway).toContain('scope:"eemf:operate"');
 expect(gateway).toContain('rian-eemf-owner-operator-v1');
 expect(gateway).toContain('RIAN_EEMF_GATEWAY_TOKEN');
 expect(gateway).not.toContain('RIAN_EEMF_ADMIN_TOKEN');
 expect(gateway).not.toContain('RIAN_ADMIN_TOKEN');
 expect(gateway).not.toContain('fleet:read');
});
test("relay and gateway restrict relative paths and sensitive files",()=>{
 expect(relay).toContain('function eemfRelativePath');
 expect(relay).toContain('EEMF path outside home');
 expect(relay).toContain('Sensitive EEMF path');
 expect(gateway).toContain('function safePath');
 expect(gateway).toContain('Sensitive path denied');
 expect(gateway).toContain('parsed.ok!==true');
});
test("local PC opt-in must be explicit and has rollback",()=>{
 expect(optin).toContain("param([switch]$Enable,[switch]$Disable");
 expect(optin).toContain("if($env:COMPUTERNAME -ine 'DESKTOP-EEMFO3L')");
 expect(optin).toContain('if(-not $Enable -and -not $Disable)');
 expect(optin).toContain('$settings.can_exec=$target');
 expect(optin).toContain('$settings.can_write=$target');
 expect(optin).toContain("Set-Acl -LiteralPath $config");
 expect(optin).toContain("mode=if($Enable){'OwnerOptIn'}else{'OwnerReverted'}");
});

test("EEMF admin route cannot bypass owner proof",()=>{
 expect(relay).toContain('if((name==="rian_write_file"||name==="rian_run_command")&&(args?.device!=="DESKTOP-EEMFO3L"||!ownerApproved))');
 expect(relay).toContain('function checkEEMFApproval(req,name,args)');
 expect(relay).toContain('if(isSensitive&&!checkEEMFApproval(req,name,args))');
 expect(relay).toContain('eemfApprovalUsed.has(claim.nonce)');
 expect(relay).toContain('createHash("sha256").update(JSON.stringify(args))');
});
test("gateway issues signed proof only in browser-approved command path",()=>{
 expect(gateway).toContain('if(ownerApproved){');
 expect(gateway).toContain('headers["x-rian-eemf-approved"]');
 expect(gateway).toContain('relay(item.operation,item.args,true)');
 expect(gateway).toContain('passwordOK(f.get("password")');
 expect(gateway).toContain('execProofKey.length>=48');
});

test("browser approval form uses same-origin referrer policy; OAuth keeps no-referrer",()=>{
 expect(gateway).toContain('function html(body,status=200,referrerPolicy="no-referrer")');
 expect(gateway).toContain('200,"same-origin")');
 expect(gateway).toContain('if(originHeader&&originHeader!==origin)');
 expect(gateway).toContain('"referrer-policy":referrerPolicy');
 expect(gateway).toContain('"referrer-policy":"no-referrer"');
});

test("central queue rejects writes and commands unless EEMF has verified owner approval",()=>{
 expect(relay).toContain('function queue(n,act,args,ownerApproved=false)');
 expect(relay).toContain('if(act==="write_file"||act==="run_command"){if(n!=="DESKTOP-EEMFO3L"||ownerApproved!==true)');
 expect(relay).toContain('const j=queue(args.device,m[name],Object.fromEntries(Object.entries(args).filter(([k])=>k!=="device")),ownerApproved);');
 expect(relay).toContain('j=queue(x.device,x.action,x.arguments||{});');
 expect(relay).toContain('if((name==="rian_write_file"||name==="rian_run_command")&&(args?.device!=="DESKTOP-EEMFO3L"||!ownerApproved))');
 expect(relay).toContain('if(isSensitive&&!checkEEMFApproval(req,name,args))');
 expect(relay).toContain('const raw=await runTool(eemfNames[name],{device:EEMF_DEVICE,...args},isSensitive);');
});
