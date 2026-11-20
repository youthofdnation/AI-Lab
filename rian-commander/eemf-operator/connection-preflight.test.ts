import {test, expect, describe} from "bun:test";
import {readFileSync} from "node:fs";
import {validateConnectivityInput, buildConnectivityPreflight} from "./connection-preflight.ts";

const NODES = ["NODE-A", "NODE-B", "NODE-C"];
const LIVE = [
  {device:"NODE-A", online:true, last_seen:"2026-11-19T00:40:00Z"},
  {device:"NODE-B", online:true, last_seen:"2026-11-19T00:40:01Z"},
  {device:"NODE-C", online:false, last_seen:null},
];
const request = (other:any = {}) => ({
  source:"NODE-A", target:"NODE-B", protocol:"tcp", port:8443,
  tls_required:true, auth_required:true, ...other
});
const report = (other:any = {}) => buildConnectivityPreflight(request(other), LIVE, NODES);

describe("RIAN Commander read-only network preflight and execution guard", () => {
  test("online devices do NOT imply their port or policy is ready", () => {
    const r = report();
    expect(r.source.online).toBe(true);
    expect(r.target.online).toBe(true);
    expect(r.result).toBe("NEEDS_VERIFIED_CONNECTION_EVIDENCE");
    expect(r.execution_ready_verified).toBe(false);
    expect(r.stop_before_job).toBe(true);
    expect(r.approval_request).toBeNull();
    expect(r.checks.find(x => x.name==="policy")?.state).toBe("unknown");
    expect(r.mode).toBe("READ_ONLY_NO_CONNECTION_PROBE");
  });

  test("reported denied policy gives minimal, separately approved, reversible intent", () => {
    const r = report({
      source_ip:"100.100.10.1", target_ip:"100.100.10.2",
      evidence:{identity:"pass", listener:"pass", policy:"fail", tcp:"fail"}
    });
    expect(r.result).toBe("TAILNET_POLICY_DENIED_REPORTED");
    expect(r.stop_before_job).toBe(true);
    expect(r.approval_request).toMatchObject({
      action:"REQUEST_SEPARATE_NETWORK_ADMIN_APPROVAL",
      source:"NODE-A", target:"NODE-B", source_ip:"100.100.10.1",
      target_ip:"100.100.10.2", capability:"tcp:8443",
      backup_existing_policy_first:true, additive_only:true,
      remove_only_added_rule_after_work:true, automatic_policy_apply:false,
      automatic_firewall_change:false
    });
    expect(r.evidence_trust).toBe("OPERATOR_REPORTED_NOT_VERIFIED");
  });

  test("TCP timeout alone must not be diagnosed as a missing Tailscale grant", () => {
    const r = report({evidence:{tcp:"fail"}});
    expect(r.result).toBe("HOST_FIREWALL_OR_ROUTE_UNDETERMINED");
    expect(r.approval_request).toBeNull();
    expect(r.execution_ready_verified).toBe(false);
    expect(r.next_action).toContain("tailnet policy");
  });

  test("offline origin or target is a blocker even when claims say success", () => {
    expect(report({source:"NODE-C",evidence:{policy:"pass",tcp:"pass"}}).result).toBe("SOURCE_OFFLINE");
    expect(report({target:"NODE-C",evidence:{policy:"pass",tcp:"pass"}}).result).toBe("TARGET_OFFLINE");
  });

  test("listener and device identity fail before transport checks", () => {
    expect(report({evidence:{listener:"fail",tcp:"fail"}}).result).toBe("SERVICE_NOT_LISTENING_REPORTED");
    expect(report({evidence:{identity:"fail",policy:"fail"}}).result).toBe("IDENTITY_MISMATCH_REPORTED");
  });

  test("TLS failures are distinct from authenticated application failures", () => {
    expect(report({evidence:{tls:"fail"}}).result).toBe("TLS_HANDSHAKE_FAILED_REPORTED");
    expect(report({evidence:{auth:"fail"}}).result).toBe("APPLICATION_AUTH_FAILED_REPORTED");
  });

  test("even all reported PASS is not counted as verified readiness", () => {
    const r = report({evidence:Object.fromEntries(["identity","listener","policy","tcp","tls","auth"].map(x=>[x,"pass"]))});
    expect(r.result).toBe("REPORTED_READY_NOT_VERIFIED");
    expect(r.execution_ready_verified).toBe(false);
    expect(r.evidence_trust).toBe("OPERATOR_REPORTED_NOT_VERIFIED");
  });

  test("strict device, protocol, port and evidence validation prevents arbitrary actions", () => {
    for (const x of [
      request({source:"UNKNOWN"}),
      request({target:"UNKNOWN"}),
      request({source:"NODE-A",target:"NODE-A"}),
      request({port:0}),request({port:65536}),request({port:"8443"}),
      request({protocol:"shell"}),request({protocol:"udp",tls_required:true}),
      request({source_ip:"100.1.1.999"}),request({target_ip:"../etc/passwd"}),
      request({evidence:{policy:"trusted"}}),request({evidence:{owner_approved:true}}),
      request({__proto__never:true})
    ]) {
      if ("__proto__never" in x) continue;
      expect(() => validateConnectivityInput(x, NODES)).toThrow();
    }
  });

  test("port and node scope come only from validated caller inputs", () => {
    const x = validateConnectivityInput(request({port:443, source_ip:"100.100.10.1"}),NODES);
    expect(x.port).toBe(443);
    expect(x.source_ip).toBe("100.100.10.1");
    expect(x.target_ip).toBeNull();
    expect(x.evidence.policy).toBe("unknown");
  });

  test("UDP does not silently claim a TCP TLS check", () => {
    const x = validateConnectivityInput(request({protocol:"udp", tls_required:false}),NODES);
    expect(x.protocol).toBe("udp");
    const result=report({protocol:"udp",tls_required:false,auth_required:false});
    expect(result.checks.find(x=>x.name==="tls")).toBeUndefined();
  });

  test("diagnostic source has no network I/O, policy mutation or remote execution",()=>{
    const s=readFileSync(new URL("./connection-preflight.ts",import.meta.url),"utf8");
    for (const unsafe of ["Bun.serve(","fetch(","runTool(","exec(","spawn(","powershell","policy_write(","tailscale set","setFirewall(","writeFile("]){
      expect(s).not.toContain(unsafe);
    }
    const r=report();
    expect(r.forbidden_automatic_actions).toContain("TAILSCALE_POLICY_WRITE");
    expect(r.forbidden_automatic_actions).toContain("WINDOWS_FIREWALL_WRITE");
  });
});
