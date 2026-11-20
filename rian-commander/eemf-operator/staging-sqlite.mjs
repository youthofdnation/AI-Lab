/**
 * RIAN Commander staging-only crash-safe SQLite store.
 * Requires a persistent Railway volume and a separately managed 32-byte AES key.
 * Does not create public credentials, send network traffic, or modify a legacy relay.
 * Node >=22.16; one writer/replica. Migration to transactional external DB required for HA.
 */
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

export class StagingSqlite {
  #db; #key; #closed=false;
  constructor({ filename, encryptionKeyHex }) {
    if (typeof filename !== 'string' || filename === ':memory:' || !filename.trim()) throw Error('PERSISTENT_DB_PATH_REQUIRED');
    if (typeof encryptionKeyHex !== 'string' || !/^[a-fA-F0-9]{64}$/.test(encryptionKeyHex)) throw Error('STORAGE_ENCRYPTION_KEY_REQUIRED');
    this.#key=Buffer.from(encryptionKeyHex,'hex');
    const file=resolve(filename);
    mkdirSync(dirname(file),{recursive:true,mode:0o700});
    this.#db=new DatabaseSync(file,{timeout:5000});
    try {
      this.#db.exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;');
      const version=Number(this.#db.prepare('PRAGMA user_version').get().user_version);
      if (version!==0 && version!==1) throw Error('UNSUPPORTED_SCHEMA_VERSION');
      const ddl=[
        'CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, cipher BLOB NOT NULL, iv BLOB NOT NULL, tag BLOB NOT NULL)',
        'CREATE TABLE IF NOT EXISTS transfers (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, owner TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, filename TEXT NOT NULL, size INTEGER NOT NULL CHECK (size>0), sha TEXT NOT NULL, chunks_total INTEGER NOT NULL, state TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL)',
        'CREATE INDEX IF NOT EXISTS idx_transfers_tenant ON transfers(tenant,expires)',
        'CREATE TABLE IF NOT EXISTS transfer_chunks (transfer_id TEXT NOT NULL REFERENCES transfers(id) ON DELETE CASCADE, idx INTEGER NOT NULL, sha TEXT NOT NULL, cipher BLOB NOT NULL, iv BLOB NOT NULL, tag BLOB NOT NULL, PRIMARY KEY(transfer_id,idx))',
        'CREATE TABLE IF NOT EXISTS transfer_dedup (tenant TEXT NOT NULL, owner TEXT NOT NULL, idempotency TEXT NOT NULL, spec TEXT NOT NULL, transfer_id TEXT NOT NULL REFERENCES transfers(id) ON DELETE CASCADE, PRIMARY KEY(tenant,owner,idempotency))',
        'CREATE TABLE IF NOT EXISTS approval_nonces (nonce TEXT PRIMARY KEY, tenant TEXT NOT NULL, expires INTEGER NOT NULL, kind TEXT NOT NULL)',
        'CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, owner TEXT NOT NULL, request_key TEXT NOT NULL, spec_sha TEXT NOT NULL, device TEXT NOT NULL, action TEXT NOT NULL, args_cipher BLOB NOT NULL, args_iv BLOB NOT NULL, args_tag BLOB NOT NULL, state TEXT NOT NULL, created INTEGER NOT NULL, deadline INTEGER NOT NULL, lease_until INTEGER, result_cipher BLOB, result_iv BLOB, result_tag BLOB, UNIQUE(tenant,owner,request_key))',
        'CREATE INDEX IF NOT EXISTS idx_jobs_pending ON jobs(tenant,device,state,created)',
        'CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, actor TEXT NOT NULL, object_id TEXT NOT NULL, action TEXT NOT NULL, ts INTEGER NOT NULL)'
      ];
      this.#db.exec(ddl.join(';')+';');
      if (version===0) this.#db.exec('PRAGMA user_version=1;');
      const sentinel=this.#db.prepare('SELECT cipher,iv,tag FROM meta WHERE key=?').get('storage-sentinel');
      if (sentinel) {
        const plaintext=this.decrypt(sentinel,'riancmd:v1:sentinel');
        if (plaintext.toString('utf8')!=='RIAN_STAGE_STORAGE_V1') throw Error('STORAGE_KEY_MISMATCH');
      } else {
        // Existing rows without a sentinel must never be silently rekeyed.
        const hasRows=this.#db.prepare('SELECT (SELECT COUNT(*) FROM transfers)+(SELECT COUNT(*) FROM jobs) AS total').get().total;
        if (hasRows) throw Error('STORAGE_SENTINEL_MISSING');
        const {cipher,iv,tag}=this.encrypt(Buffer.from('RIAN_STAGE_STORAGE_V1'),'riancmd:v1:sentinel');
        this.#db.prepare('INSERT INTO meta(key,cipher,iv,tag) VALUES(?,?,?,?)').run('storage-sentinel',cipher,iv,tag);
      }
      // After restart we cannot know whether an agent executed an in-flight job.
      // Never automatically requeue or replay it.
      this.#db.prepare("UPDATE jobs SET state='UNKNOWN_DO_NOT_RETRY' WHERE state IN ('RUNNING','CANCEL_REQUESTED')").run();
    } catch (err) { this.#db.close();this.#closed=true;throw err; }
  }
  get db() { if(this.#closed)throw Error('STORAGE_CLOSED');return this.#db; }
  transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result=fn(); this.db.exec('COMMIT'); return result; }
    catch (err) { this.db.exec('ROLLBACK'); throw err; }
  }
  encrypt(plain,aad) {
    const iv=randomBytes(12), enc=createCipheriv('aes-256-gcm',this.#key,iv);
    enc.setAAD(Buffer.from(aad));
    const cipher=Buffer.concat([enc.update(plain),enc.final()]);
    return {cipher,iv,tag:enc.getAuthTag()};
  }
  decrypt(value,aad) {
    try {
      const dec=createDecipheriv('aes-256-gcm',this.#key,Buffer.from(value.iv));
      dec.setAAD(Buffer.from(aad)); dec.setAuthTag(Buffer.from(value.tag));
      return Buffer.concat([dec.update(Buffer.from(value.cipher)),dec.final()]);
    } catch { throw Error('STORAGE_INTEGRITY_FAILED'); }
  }
  audit(tenant,actor,objectId,action,now) {
    // IDs and action names only: never log tokens, proofs, paths, command args or file contents.
    this.db.prepare('INSERT INTO audit(tenant,actor,object_id,action,ts) VALUES(?,?,?,?,?)').run(tenant,actor,objectId,action,now);
  }
  sweep(now) {
    this.transaction(()=>{
      this.db.prepare('DELETE FROM transfers WHERE expires <= ?').run(now);
      this.db.prepare('DELETE FROM approval_nonces WHERE expires <= ?').run(now);
      this.db.prepare("DELETE FROM jobs WHERE deadline < ? AND state IN ('DONE','CANCELLED','EXPIRED','UNKNOWN_DO_NOT_RETRY')").run(now-86400);
    });
  }
  close() {if(!this.#closed){this.#closed=true;this.#db.close();}}
}
