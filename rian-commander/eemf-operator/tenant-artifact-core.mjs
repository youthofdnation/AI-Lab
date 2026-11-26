/**
 * RIAN Commander v2 tenant-scoped artifact transport (staging-only core).
 * No global administrator bypass, local file access, shell execution, or network ACL mutation.
 * This intentionally does not provide a durable store or an activated HTTP route.
 */
import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';

const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const GRANT_AUDIENCE = 'rian-tenant-artifact-v1';
export const ARTIFACT_CHUNK_BYTES = 64 * 1024;
export const ARTIFACT_MAX_BYTES = 8 * 1024 * 1024;
export const ARTIFACT_TTL_SECONDS = 3600;

function denied() { throw new Error('ACCESS_DENIED'); }
function requireId(value) { if (typeof value !== 'string' || !ID.test(value)) throw new Error('INVALID_ID'); return value; }
function isSha(value) { return typeof value === 'string' && SHA256.test(value); }
function digest(buf) { return createHash('sha256').update(buf).digest('hex'); }
function sameHex(a, b) { return typeof a === 'string' && typeof b === 'string' && SHA256.test(a) && SHA256.test(b) && timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex')); }
function fileLabel(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 120 || value === '.' || value === '..' || /[\\/\x00-\x1f\x7f<>:"|?*]/.test(value)) throw new Error('INVALID_ARTIFACT_NAME');
  return value.normalize('NFC');
}

/** Principals are loaded from server-side config. Tokens are hashed, never persisted in plaintext. */
export class TenantDirectory {
  #principals = [];
  #devices = new Map();
  #authentic = new WeakSet();
  constructor({ principals, devices }) {
    if (!Array.isArray(principals) || !Array.isArray(devices) || !principals.length || !devices.length) throw new Error('INVALID_DIRECTORY');
    for (const d of devices) {
      const id = requireId(d.id), tenantId = requireId(d.tenantId);
      if (this.#devices.has(id)) throw new Error('DUPLICATE_DEVICE');
      this.#devices.set(id, Object.freeze({ id, tenantId }));
    }
    const names = new Set(), tokenHashes = new Set();
    for (const p of principals) {
      const id = requireId(p.id), tenantId = requireId(p.tenantId);
      if (!['owner', 'agent'].includes(p.kind) || !isSha(p.tokenSha256)) throw new Error('INVALID_PRINCIPAL');
      if (names.has(id) || tokenHashes.has(p.tokenSha256)) throw new Error('DUPLICATE_PRINCIPAL');
      const deviceId = p.kind === 'agent' ? requireId(p.deviceId) : null;
      if ((p.kind === 'owner' && p.deviceId != null) || (deviceId && this.#devices.get(deviceId)?.tenantId !== tenantId)) throw new Error('INVALID_PRINCIPAL_DEVICE');
      const actor = Object.freeze({ id, tenantId, kind: p.kind, deviceId });
      this.#principals.push({ tokenSha256: p.tokenSha256, actor });
      this.#authentic.add(actor);
      names.add(id); tokenHashes.add(p.tokenSha256);
    }
  }
  authenticate(header) {
    const match = typeof header === 'string' && /^Bearer ([A-Za-z0-9_-]{40,256})$/.exec(header);
    if (!match) denied();
    const hash = Buffer.from(digest(Buffer.from(match[1])), 'hex');
    for (const p of this.#principals) {
      if (timingSafeEqual(hash, Buffer.from(p.tokenSha256, 'hex'))) return p.actor;
    }
    denied();
  }
  /** Trusted server adapter only, after a password or passkey session was verified. */
  ownerFromVerifiedSession(tenantId,ownerId) {
    const p=this.#principals.find(x=>x.actor.kind==='owner'&&x.actor.tenantId===tenantId&&x.actor.id===ownerId);
    if(!p)denied();
    return p.actor;
  }
  assertActor(actor) { if (!actor || typeof actor !== 'object' || !this.#authentic.has(actor)) denied(); }
  assertOwner(actor) { this.assertActor(actor); if (actor.kind !== 'owner') denied(); }
  assertDevice(tenantId, deviceId) {
    if (this.#devices.get(deviceId)?.tenantId !== tenantId) denied();
  }
  assertAgent(actor, tenantId, deviceId) {
    this.assertActor(actor);
    if (actor.kind !== 'agent' || actor.tenantId !== tenantId || actor.deviceId !== deviceId) denied();
  }
  assertViewer(actor, record) {
    this.assertActor(actor);
    if (actor.tenantId !== record.tenantId) denied();
    if (actor.kind === 'owner') return;
    if (actor.kind !== 'agent' || ![record.sourceDeviceId, record.targetDeviceId].includes(actor.deviceId)) denied();
  }
  listOwnDevices(actor) {
    this.assertOwner(actor);
    return [...this.#devices.values()].filter(d => d.tenantId === actor.tenantId).map(d => ({ id: d.id }));
  }
}

/** Only a privileged owner-approval handler may hold this signing secret or call issue(). */
export class OwnerTransferApproval {
  #secret;
  constructor(secret) { if (typeof secret !== 'string' || Buffer.byteLength(secret) < 48) throw new Error('INVALID_GRANT_SECRET'); this.#secret = secret; }
  issue(scope) {
    if (!scope || Object.keys(scope).sort().join(',') !== 'expiresAt,nonce,ownerId,sha256,sizeBytes,sourceDeviceId,targetDeviceId,tenantId') throw new Error('INVALID_GRANT');
    if (!isSha(scope.sha256) || !Number.isInteger(scope.expiresAt) || !/^[a-f0-9]{32}$/.test(scope.nonce)) throw new Error('INVALID_GRANT');
    for (const k of ['tenantId', 'ownerId', 'sourceDeviceId', 'targetDeviceId']) requireId(scope[k]);
    if (!Number.isSafeInteger(scope.sizeBytes) || scope.sizeBytes < 1 || scope.sizeBytes > ARTIFACT_MAX_BYTES) throw new Error('INVALID_GRANT');
    const encoded = Buffer.from(JSON.stringify({aud:GRANT_AUDIENCE,...scope})).toString('base64url');
    const signature = createHmac('sha256', this.#secret).update(encoded).digest('hex');
    return encoded + '.' + signature;
  }
  verify(proof, nowSeconds) {
    if (typeof proof !== 'string' || proof.length > 2048) denied();
    const parts = proof.split('.');
    if (parts.length !== 2 || !B64URL.test(parts[0]) || !SHA256.test(parts[1])) denied();
    const expected = createHmac('sha256', this.#secret).update(parts[0]).digest('hex');
    if (!sameHex(expected, parts[1])) denied();
    let claim;
    try { claim = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')); } catch { denied(); }
    if (!claim || typeof claim !== 'object' || Array.isArray(claim) || claim.aud !== GRANT_AUDIENCE) denied();
    if (!Number.isInteger(claim.expiresAt) || claim.expiresAt <= nowSeconds || claim.expiresAt > nowSeconds + 300 || !/^[a-f0-9]{32}$/.test(claim.nonce || '')) denied();
    if (!isSha(claim.sha256) || !Number.isSafeInteger(claim.sizeBytes)) denied();
    for (const k of ['tenantId', 'ownerId', 'sourceDeviceId', 'targetDeviceId']) requireId(claim[k]);
    if (Object.keys(claim).sort().join(',') !== 'aud,expiresAt,nonce,ownerId,sha256,sizeBytes,sourceDeviceId,targetDeviceId,tenantId') denied();
    return claim;
  }
}

/**
 * Staging broker: bounded process-memory storage. Safe to evaluate policy, NOT durable.
 * Production adapter needs atomic, per-tenant persisted records, encrypted object storage and durable replay cache.
 */
export class TenantArtifactBroker {
  #directory; #approval; #clock;
  #records = new Map(); #idempotency = new Map(); #usedGrants = new Map();
  constructor({ directory, approval, clock = () => Date.now() }) {
    if (!(directory instanceof TenantDirectory) || !(approval instanceof OwnerTransferApproval) || typeof clock !== 'function') throw new Error('INVALID_BROKER_CONFIG');
    this.#directory = directory; this.#approval = approval; this.#clock = clock;
  }
  #seconds() { return Math.floor(this.#clock() / 1000); }
  #live(id) {
    const record = this.#records.get(id);
    if (!record || record.expiresAt <= this.#seconds()) throw new Error('NOT_FOUND_OR_EXPIRED');
    return record;
  }
  #summary(rec) {
    return { transferId: rec.id, state: rec.state, sourceDeviceId: rec.sourceDeviceId, targetDeviceId: rec.targetDeviceId,
      name: rec.name, sizeBytes: rec.sizeBytes, sha256: rec.sha256, chunkBytes: ARTIFACT_CHUNK_BYTES,
      totalChunks: rec.totalChunks, uploadedChunks: rec.chunks.size, expiresAt: rec.expiresAt };
  }
  begin({ actor, sourceDeviceId, targetDeviceId, name, sizeBytes, sha256, approvalProof, idempotencyKey }) {
    this.#directory.assertOwner(actor);
    requireId(sourceDeviceId); requireId(targetDeviceId);
    if (sourceDeviceId === targetDeviceId) throw new Error('DISTINCT_DEVICES_REQUIRED');
    this.#directory.assertDevice(actor.tenantId, sourceDeviceId);
    this.#directory.assertDevice(actor.tenantId, targetDeviceId);
    const filename = fileLabel(name);
    if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 1 || sizeBytes > ARTIFACT_MAX_BYTES || !isSha(sha256)) throw new Error('INVALID_MANIFEST');
    if (typeof idempotencyKey !== 'string' || !/^[A-Za-z0-9_-]{16,80}$/.test(idempotencyKey)) throw new Error('INVALID_IDEMPOTENCY_KEY');
    const dedupeKey = actor.tenantId + ':' + actor.id + ':' + idempotencyKey;
    const spec = JSON.stringify([sourceDeviceId,targetDeviceId,filename,sizeBytes,sha256]);
    const existing = this.#idempotency.get(dedupeKey);
    if (existing) {
      if (existing.spec !== spec) throw new Error('IDEMPOTENCY_CONFLICT');
      const record = this.#live(existing.id);
      return this.#summary(record);
    }
    const now = this.#seconds();
    const grant = this.#approval.verify(approvalProof, now);
    if (grant.tenantId !== actor.tenantId || grant.ownerId !== actor.id || grant.sourceDeviceId !== sourceDeviceId ||
      grant.targetDeviceId !== targetDeviceId || grant.sizeBytes !== sizeBytes || grant.sha256 !== sha256) denied();
    if (this.#usedGrants.has(grant.nonce)) throw new Error('APPROVAL_REPLAY');
    const rec = { id: randomUUID(), tenantId: actor.tenantId, sourceDeviceId, targetDeviceId,
      name: filename, sizeBytes, sha256, totalChunks: Math.ceil(sizeBytes / ARTIFACT_CHUNK_BYTES),
      expiresAt: now + ARTIFACT_TTL_SECONDS, state: 'UPLOADING', chunks: new Map() };
    this.#usedGrants.set(grant.nonce, grant.expiresAt);
    this.#records.set(rec.id,rec);
    this.#idempotency.set(dedupeKey,{id:rec.id,spec});
    return this.#summary(rec);
  }
  status(actor, transferId) {
    const rec = this.#live(transferId);
    this.#directory.assertViewer(actor, rec);
    return this.#summary(rec);
  }
  upload({ actor, transferId, index, base64, chunkSha256 }) {
    const rec = this.#live(transferId);
    this.#directory.assertAgent(actor, rec.tenantId, rec.sourceDeviceId);
    if (rec.state !== 'UPLOADING') throw new Error('TRANSFER_NOT_WRITABLE');
    if (!Number.isInteger(index) || index < 0 || index >= rec.totalChunks || !isSha(chunkSha256)) throw new Error('INVALID_CHUNK');
    const expectedBytes = Math.min(ARTIFACT_CHUNK_BYTES, rec.sizeBytes - index * ARTIFACT_CHUNK_BYTES);
    if (typeof base64 !== 'string' || base64.length > Math.ceil(ARTIFACT_CHUNK_BYTES / 3) * 4 + 4) throw new Error('INVALID_CHUNK');
    const bytes = Buffer.from(base64, 'base64');
    if (bytes.length !== expectedBytes || bytes.toString('base64') !== base64 || !sameHex(digest(bytes), chunkSha256)) throw new Error('CHUNK_HASH_OR_LENGTH_MISMATCH');
    const existing = rec.chunks.get(index);
    if (existing) {
      if (existing.sha256 === chunkSha256 && existing.base64 === base64) return { state:'ALREADY_PRESENT', index };
      throw new Error('CHUNK_REPLAY_CONFLICT');
    }
    rec.chunks.set(index,{base64,sha256:chunkSha256});
    return { state:'STORED', index };
  }
  finalize(actor, transferId) {
    const rec = this.#live(transferId);
    this.#directory.assertAgent(actor, rec.tenantId, rec.sourceDeviceId);
    if (rec.state === 'READY' || rec.state === 'DELIVERED') return this.#summary(rec);
    if (rec.state !== 'UPLOADING') throw new Error('TRANSFER_NOT_WRITABLE');
    if (rec.chunks.size !== rec.totalChunks) throw new Error('CHUNKS_MISSING');
    const hasher = createHash('sha256');
    for (let i = 0; i < rec.totalChunks; i++) {
      const chunk = rec.chunks.get(i);
      if (!chunk) throw new Error('CHUNKS_MISSING');
      hasher.update(Buffer.from(chunk.base64,'base64'));
    }
    if (!sameHex(hasher.digest('hex'), rec.sha256)) {
      rec.state = 'FAILED_INTEGRITY';
      throw new Error('FULL_HASH_MISMATCH');
    }
    rec.state = 'READY';
    return this.#summary(rec);
  }
  download({ actor, transferId, index }) {
    const rec = this.#live(transferId);
    this.#directory.assertAgent(actor, rec.tenantId, rec.targetDeviceId);
    if (rec.state !== 'READY') throw new Error('TRANSFER_NOT_READY');
    if (!Number.isInteger(index) || index < 0 || index >= rec.totalChunks) throw new Error('INVALID_CHUNK');
    const chunk = rec.chunks.get(index);
    if (!chunk) throw new Error('CHUNKS_MISSING');
    return { index, ...chunk };
  }
  acknowledge({ actor, transferId, receivedSha256 }) {
    const rec = this.#live(transferId);
    this.#directory.assertAgent(actor, rec.tenantId, rec.targetDeviceId);
    if (rec.state === 'DELIVERED' && sameHex(receivedSha256,rec.sha256)) return this.#summary(rec);
    if (rec.state !== 'READY') throw new Error('TRANSFER_NOT_READY');
    if (!sameHex(receivedSha256,rec.sha256)) throw new Error('DESTINATION_HASH_MISMATCH');
    rec.state = 'DELIVERED';
    rec.chunks.clear();
    return this.#summary(rec);
  }
  cancel(actor, transferId) {
    this.#directory.assertOwner(actor);
    const rec = this.#live(transferId);
    if (rec.tenantId !== actor.tenantId) denied();
    if (rec.state === 'DELIVERED') throw new Error('DELIVERED_CANNOT_CANCEL');
    rec.state = 'CANCELLED'; rec.chunks.clear();
    return this.#summary(rec);
  }
  sweep() {
    const now = this.#seconds();
    for (const [id, rec] of this.#records) if (rec.expiresAt <= now) this.#records.delete(id);
    for (const [key, value] of this.#idempotency) if (!this.#records.has(value.id)) this.#idempotency.delete(key);
    for (const [nonce, exp] of this.#usedGrants) if (exp <= now) this.#usedGrants.delete(nonce);
  }
}
