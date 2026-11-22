/**
 * Health store (node:sqlite). Every row carries its tenant; every read takes a tenant.
 * Sample payloads, incident labels and outbox messages are encrypted with the tenant key and
 * bound (AAD) to tenant + row identity, so rows cannot be swapped between tenants or devices.
 */
import {DatabaseSync} from 'node:sqlite';
import {TenantVault,newId} from './health-core.mjs';

const DAY=86400;

export class HealthStore{
  #vault;
  constructor({filename,vault}){
    if(!(vault instanceof TenantVault))throw Error('INVALID_VAULT');
    this.#vault=vault;
    this.db=new DatabaseSync(filename);
    for(const sql of [
      'PRAGMA journal_mode=WAL','PRAGMA foreign_keys=ON',
      'CREATE TABLE IF NOT EXISTS samples (tenant TEXT NOT NULL, device TEXT NOT NULL, ts INTEGER NOT NULL, ok INTEGER NOT NULL, cipher BLOB NOT NULL, iv BLOB NOT NULL, tag BLOB NOT NULL, PRIMARY KEY(tenant,device,ts))',
      'CREATE TABLE IF NOT EXISTS device_seen (tenant TEXT NOT NULL, device TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, last_ok INTEGER, PRIMARY KEY(tenant,device))',
      "CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, device TEXT NOT NULL, type TEXT NOT NULL, key_id TEXT NOT NULL, label_cipher BLOB NOT NULL, label_iv BLOB NOT NULL, label_tag BLOB NOT NULL, state TEXT NOT NULL CHECK(state IN ('OPEN','RESOLVED')), opened_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, resolved_at INTEGER, peak REAL)",
      "CREATE UNIQUE INDEX IF NOT EXISTS one_open_incident ON incidents(tenant,device,type,key_id) WHERE state='OPEN'",
      'CREATE INDEX IF NOT EXISTS incidents_by_time ON incidents(tenant,opened_at)',
      "CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, incident_id TEXT NOT NULL, event TEXT NOT NULL CHECK(event IN ('OPENED','RESOLVED')), created INTEGER NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, cipher BLOB NOT NULL, iv BLOB NOT NULL, tag BLOB NOT NULL, UNIQUE(incident_id,event))"
    ])this.db.exec(sql);
  }
  close(){this.db.close();}
  transaction(fn){
    this.db.exec('BEGIN IMMEDIATE');
    try{const r=fn();this.db.exec('COMMIT');return r;}catch(e){try{this.db.exec('ROLLBACK');}catch{}throw e;}
  }
  #enc(tenant,aad,obj){return this.#vault.encrypt(tenant,aad,JSON.stringify(obj));}
  #dec(tenant,aad,row,prefix=''){return JSON.parse(this.#vault.decrypt(tenant,aad,{cipher:row[prefix+'cipher'],iv:row[prefix+'iv'],tag:row[prefix+'tag']}).toString('utf8'));}
  lookup(tenant,text){return this.#vault.lookup(tenant,text);}

  /** Idempotent: a resent sample with the same timestamp is ignored. Returns true if stored. */
  insertSample(tenant,device,sample){
    const e=this.#enc(tenant,`sample|${tenant}|${device}|${sample.ts}`,sample);
    const r=this.db.prepare('INSERT OR IGNORE INTO samples(tenant,device,ts,ok,cipher,iv,tag) VALUES(?,?,?,?,?,?,?)').run(tenant,device,sample.ts,sample.collection.ok?1:0,e.cipher,e.iv,e.tag);
    if(r.changes===1)this.db.prepare('INSERT INTO device_seen(tenant,device,first_seen,last_seen,last_ok) VALUES(?,?,?,?,?) ON CONFLICT(tenant,device) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen),last_ok=CASE WHEN excluded.last_seen>=last_seen THEN excluded.last_ok ELSE last_ok END')
      .run(tenant,device,sample.ts,sample.ts,sample.collection.ok?1:0);
    return r.changes===1;
  }
  samples(tenant,device,from,to){
    return this.db.prepare('SELECT ts,cipher,iv,tag FROM samples WHERE tenant=? AND device=? AND ts>=? AND ts<=? ORDER BY ts').all(tenant,device,from,to)
      .map(r=>this.#dec(tenant,`sample|${tenant}|${device}|${r.ts}`,r));
  }
  sampleCounts(tenant,device,from,to){
    return this.db.prepare('SELECT COUNT(*) AS n, SUM(ok) AS ok FROM samples WHERE tenant=? AND device=? AND ts>=? AND ts<=?').get(tenant,device,from,to);
  }
  seen(tenant){return this.db.prepare('SELECT device,first_seen,last_seen,last_ok FROM device_seen WHERE tenant=?').all(tenant);}
  lastSeen(tenant,device){return this.db.prepare('SELECT last_seen FROM device_seen WHERE tenant=? AND device=?').get(tenant,device)?.last_seen??null;}

  openIncidents(tenant,device){
    return this.db.prepare("SELECT * FROM incidents WHERE tenant=? AND device=? AND state='OPEN'").all(tenant,device).map(r=>this.#incident(r));
  }
  openIncident(tenant,device,type,key,label,ts,peak){
    const id=newId(),e=this.#enc(tenant,`incident|${tenant}|${id}`,{label});
    this.db.prepare("INSERT INTO incidents(id,tenant,device,type,key_id,label_cipher,label_iv,label_tag,state,opened_at,last_seen_at,peak) VALUES(?,?,?,?,?,?,?,?,'OPEN',?,?,?)")
      .run(id,tenant,device,type,this.lookup(tenant,key),e.cipher,e.iv,e.tag,ts,ts,peak??null);
    return id;
  }
  touchIncident(id,ts,peak){this.db.prepare('UPDATE incidents SET last_seen_at=MAX(last_seen_at,?),peak=CASE WHEN ? IS NULL THEN peak WHEN peak IS NULL OR ?>peak THEN ? ELSE peak END WHERE id=?').run(ts,peak??null,peak??null,peak??null,id);}
  resolveIncident(id,ts){return this.db.prepare("UPDATE incidents SET state='RESOLVED',resolved_at=? WHERE id=? AND state='OPEN'").run(ts,id).changes===1;}
  incidents(tenant,from,to){
    return this.db.prepare("SELECT * FROM incidents WHERE tenant=? AND opened_at<=? AND (resolved_at IS NULL OR resolved_at>=?) ORDER BY opened_at").all(tenant,to,from).map(r=>this.#incident(r));
  }
  #incident(r){
    const {label}=this.#dec(r.tenant,`incident|${r.tenant}|${r.id}`,r,'label_');
    return {id:r.id,device:r.device,type:r.type,keyId:r.key_id,label,state:r.state,openedAt:r.opened_at,lastSeenAt:r.last_seen_at,resolvedAt:r.resolved_at,peak:r.peak};
  }

  /** One message per incident transition (UNIQUE(incident_id,event)) — duplicates are impossible. */
  addOutbox(tenant,incidentId,event,message,status,now){
    const id=newId(),e=this.#enc(tenant,`outbox|${tenant}|${id}`,message);
    return this.db.prepare('INSERT OR IGNORE INTO outbox(id,tenant,incident_id,event,created,status,cipher,iv,tag) VALUES(?,?,?,?,?,?,?,?,?)').run(id,tenant,incidentId,event,now,status,e.cipher,e.iv,e.tag).changes===1?id:null;
  }
  outbox(tenant,status=null){
    return this.db.prepare('SELECT * FROM outbox WHERE tenant=?'+(status?' AND status=?':'')+' ORDER BY created').all(...(status?[tenant,status]:[tenant]))
      .map(r=>({id:r.id,incidentId:r.incident_id,event:r.event,created:r.created,status:r.status,attempts:r.attempts,message:this.#dec(tenant,`outbox|${tenant}|${r.id}`,r)}));
  }
  setOutboxStatus(id,status){this.db.prepare('UPDATE outbox SET status=?,attempts=attempts+1 WHERE id=?').run(status,id);}

  /** Retention candidates: raw samples 30 days, incidents/outbox 12 months. */
  purge(now,{sampleDays=30,historyDays=365}={}){
    return this.transaction(()=>({
      samples:this.db.prepare('DELETE FROM samples WHERE ts<?').run(now-sampleDays*DAY).changes,
      incidents:this.db.prepare("DELETE FROM incidents WHERE state='RESOLVED' AND resolved_at<?").run(now-historyDays*DAY).changes,
      outbox:this.db.prepare('DELETE FROM outbox WHERE created<?').run(now-historyDays*DAY).changes}));
  }
}
