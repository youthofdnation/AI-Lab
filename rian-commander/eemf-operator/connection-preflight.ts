/**
 * RIAN Commander read-only inter-device connectivity preflight.
 *
 * This examines relay heartbeats and explicitly labelled operator-supplied
 * observations. It DOES NOT probe a remote port, read a tailnet policy,
 * grant permissions, modify an ACL/firewall, or execute an agent command.
 * A TCP timeout alone must NEVER be reported as proof of a missing ACL.
 */
const CHECKS = ["identity", "listener", "policy", "tcp", "tls", "auth"];
const VALUES = ["pass", "fail", "unknown"];

function assertObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Invalid " + label);
  }
}
function assertFields(value, accepted, label) {
  for (const name of Object.keys(value)) {
    if (!accepted.includes(name)) throw new Error("Unrecognized " + label + " field");
  }
}
function ipv4(value) {
  if (typeof value !== "string" || value.length > 15 || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    return false;
  }
  return value.split(".").every(part => Number(part) <= 255 && Number(part) >= 0 && (part === "0" || !part.startsWith("0")));
}
export function validateConnectivityInput(request, registered) {
  assertObject(request, "preflight request");
  if (!Array.isArray(registered) || registered.some(x => typeof x !== "string")) throw new Error("Invalid device registry");
  assertFields(request, ["source", "target", "protocol", "port", "evidence", "source_ip", "target_ip", "tls_required", "auth_required"], "request");
  const {source, target, port} = request;
  if (!registered.includes(source) || !registered.includes(target) || source === target) {
    throw new Error("Select two different registered devices");
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid destination port");
  const protocol = request.protocol === undefined ? "tcp" : request.protocol;
  if (protocol !== "tcp" && protocol !== "udp") throw new Error("Unsupported protocol");
  const tls_required = request.tls_required === undefined ? protocol === "tcp" : request.tls_required;
  const auth_required = request.auth_required === undefined ? true : request.auth_required;
  if (typeof tls_required !== "boolean" || typeof auth_required !== "boolean") throw new Error("Invalid application check flags");
  if (protocol === "udp" && tls_required) throw new Error("TCP TLS validation is not applicable to UDP");
  if (request.source_ip !== undefined && !ipv4(request.source_ip)) throw new Error("Invalid source IP");
  if (request.target_ip !== undefined && !ipv4(request.target_ip)) throw new Error("Invalid destination IP");
  const evidence = request.evidence === undefined ? {} : request.evidence;
  assertObject(evidence, "reported evidence");
  assertFields(evidence, CHECKS, "evidence");
  for (const value of Object.values(evidence)) {
    if (!VALUES.includes(value)) throw new Error("Evidence must be pass, fail or unknown");
  }
  return {
    source, target, port, protocol, tls_required, auth_required,
    source_ip: request.source_ip || null,
    target_ip: request.target_ip || null,
    evidence: Object.fromEntries(CHECKS.map(check => [check, evidence[check] || "unknown"])),
  };
}
function requireActiveDevice(heartbeat, label) {
  assertObject(heartbeat, label + " heartbeat");
  if (typeof heartbeat.online !== "boolean") throw new Error("Invalid " + label + " online state");
  return {device: heartbeat.device, online: heartbeat.online, last_seen: heartbeat.last_seen || null};
}
function recommendBlocked(code, scope) {
  const descriptions = {
    SOURCE_OFFLINE: "Verify the originating agent is connected before any network changes.",
    TARGET_OFFLINE: "Verify the destination agent is connected before any network changes.",
    IDENTITY_MISMATCH_REPORTED: "Recheck source and destination node identities and device ownership.",
    SERVICE_NOT_LISTENING_REPORTED: "Inspect the intended service's listener on the destination without expanding firewall rules.",
    TAILNET_POLICY_DENIED_REPORTED: "Ask the tailnet administrator to verify the current policy and, if needed, approve only this node pair and service port.",
    HOST_FIREWALL_OR_ROUTE_UNDETERMINED: "Run an authorized TCP/UDP check from the source; inspect route, tailnet policy, destination listener and host firewall independently.",
    TLS_HANDSHAKE_FAILED_REPORTED: "Check certificate, server identity and client-to-server TLS negotiation before changing any access control.",
    APPLICATION_AUTH_FAILED_REPORTED: "Check authentication and authorization; network access alone does not grant application permissions.",
  };
  return {next_action: descriptions[code], approval_request: code === "TAILNET_POLICY_DENIED_REPORTED" ? {
    action: "REQUEST_SEPARATE_NETWORK_ADMIN_APPROVAL",
    provider: "tailscale_or_equivalent",
    source: scope.source, target: scope.target,
    source_ip: scope.source_ip, target_ip: scope.target_ip,
    capability: scope.protocol + ":" + scope.port,
    backup_existing_policy_first: true,
    additive_only: true,
    remove_only_added_rule_after_work: true,
    verify_tcp_tls_auth_after_policy_change: true,
    automatic_policy_apply: false,
    automatic_firewall_change: false,
  } : null};
}
/**
 * Live heartbeat data is verified by the relay. Evidence is NOT verified here;
 * it is an operator claim, even when the claim is "pass".
 */
export function buildConnectivityPreflight(request, liveDevices, registeredDevices) {
  const scope = validateConnectivityInput(request, registeredDevices);
  if (!Array.isArray(liveDevices)) throw new Error("Invalid heartbeat listing");
  const src = liveDevices.find(x => x.device === scope.source);
  const dst = liveDevices.find(x => x.device === scope.target);
  if (!src || !dst) throw new Error("Device heartbeat unavailable");
  const source = requireActiveDevice(src, "source");
  const target = requireActiveDevice(dst, "destination");
  const values = {...scope.evidence};
  const checks = [
    {name: "source_online", state: source.online ? "pass" : "fail", origin: "relay_heartbeat"},
    {name: "target_online", state: target.online ? "pass" : "fail", origin: "relay_heartbeat"},
    ...CHECKS.filter(name => (name !== "tls" || scope.tls_required) && (name !== "auth" || scope.auth_required))
      .map(name => ({name, state: values[name], origin: "operator_report_unverified"})),
  ];
  let code = "NEEDS_VERIFIED_CONNECTION_EVIDENCE";
  if (!source.online) code = "SOURCE_OFFLINE";
  else if (!target.online) code = "TARGET_OFFLINE";
  else if (values.identity === "fail") code = "IDENTITY_MISMATCH_REPORTED";
  else if (values.listener === "fail") code = "SERVICE_NOT_LISTENING_REPORTED";
  else if (values.policy === "fail") code = "TAILNET_POLICY_DENIED_REPORTED";
  else if (values.tcp === "fail") code = "HOST_FIREWALL_OR_ROUTE_UNDETERMINED";
  else if (scope.tls_required && values.tls === "fail") code = "TLS_HANDSHAKE_FAILED_REPORTED";
  else if (scope.auth_required && values.auth === "fail") code = "APPLICATION_AUTH_FAILED_REPORTED";
  else {
    const required = CHECKS.filter(name => (name !== "tls" || scope.tls_required) && (name !== "auth" || scope.auth_required));
    if (required.every(name => values[name] === "pass")) code = "REPORTED_READY_NOT_VERIFIED";
  }
  const stop = !["NEEDS_VERIFIED_CONNECTION_EVIDENCE", "REPORTED_READY_NOT_VERIFIED"].includes(code);
  const remedy = recommendBlocked(code, scope);
  return {
    schema: "rian-connectivity-preflight-v1",
    mode: "READ_ONLY_NO_CONNECTION_PROBE",
    source, target,
    service: {protocol: scope.protocol, port: scope.port, tls_required: scope.tls_required, auth_required: scope.auth_required},
    result: code,
    execution_ready_verified: false,
    stop_before_job: stop || code === "NEEDS_VERIFIED_CONNECTION_EVIDENCE",
    reason: stop ? "A reported blocker requires verification or remediation." :
      code === "REPORTED_READY_NOT_VERIFIED" ? "All application-layer checks are operator-reported, not independently verified." :
      "Required source-to-destination observations are missing.",
    evidence_trust: "OPERATOR_REPORTED_NOT_VERIFIED",
    checks,
    ...(remedy.next_action ? {next_action: remedy.next_action} : {
      next_action: "Request scoped, read-only policy/listener/TCP/TLS/auth checks from authorized endpoint agents before the job.",
    }),
    approval_request: remedy.approval_request,
    forbidden_automatic_actions: ["TAILSCALE_POLICY_WRITE", "WINDOWS_FIREWALL_WRITE", "PORT_WILDCARD", "UNSCOPED_REMOTE_SHELL"],
  };
}
