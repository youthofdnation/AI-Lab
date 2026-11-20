/**
 * Persistent, tenant-scoped artifact broker for a single-replica staging service.
 * Uses atomic SQLite commits, AES-256-GCM encrypted chunks, durable approvals
 * and dedup; no local file path or agent command is accepted here.
 */
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import {TenantArtifactBroker, TenantDirectory, OwnerTransferApproval, ARTIFACT_CHUNK_BYTES, ARTIFACT_MAX_BYTES, ARTIFACT_TTL_SECONDS} from './tenant-artifact-core.mjs';
import {StagingSqlite} from './staging-sqlite.mjs';
const SHA=/^[a-f0-9]{64}$/, KEY=/^[A-Za-z0-9_-]{16,80}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
const equal=(a,b)=>typeof a==='string'&&typeof b==='string'&&SHA.test(a)&&SHA.test(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const reject=()=>{throw Error('ACCESS_DENIED')};
function filename(x){
 if(typeof x!=='string'||!x||x.length>120||x==='.'||x==='..'||/[\\/\x00-\x1f\x7f<>:"|?*]/.test(x))throw Error('INVALID_ARTIFACT_NAME');
 return x.normalize('NFC');
}
export class DurableTenantArtifactBroker extends TenantArtifactBroker {
 #store;#directory;#approval;#clock;
 constructor({directory,approval,store,clock=()=>Date.now()}){
   super({directory,approval,clock});
   if(!(store instanceof StagingSqlite)||typeof clock!=='function')throw Error('INVALID_DURABLE_CONFIG');
   this.#store=store;this.#directory=directory;this.#approval=approval;this.#clock=clock;
 }
 #now(){return Math.floor(this.#clock()/1000);}
 #load(actor,id){
   this.#directory.assertActor(actor);
   const rec=this.#store.db.prepare('SELECT * FROM transfers WHERE id=? AND tenant=?').get(id,actor.tenantId);
   if(!rec||rec.expires<=this.#now())throw Error('NOT_FOUND_OR_EXPIRED');
   this.#directory.assertViewer(actor,{tenantId:rec.tenant,sourceDeviceId:rec.src,targetDeviceId:rec.dst});
   return rec;
 }
 #summary(rec){
   const count=Number(this.#store.db.prepare('SELECT COUNT(*) AS n FROM transfer_chunks WHERE transfer_id=?').get(rec.id).n);
   return {transferId:rec.id,state:rec.state,sourceDeviceId:rec.src,targetDeviceId:rec.dst,name:rec.filename,
    sizeBytes:rec.size,sha256:rec.sha,chunkBytes:ARTIFACT_CHUNK_BYTES,totalChunks:rec.chunks_total,
    uploadedChunks:count,expiresAt:rec.expires};
 }
 begin({actor,sourceDeviceId,targetDeviceId,name,sizeBytes,sha256,approvalProof,idempotencyKey}){
   this.#directory.assertOwner(actor);
   this.#directory.assertDevice(actor.tenantId,sourceDeviceId);
   this.#directory.assertDevice(actor.tenantId,targetDeviceId);
   if(sourceDeviceId===targetDeviceId)throw Error('DISTINCT_DEVICES_REQUIRED');
   const safeName=filename(name);
   if(!Number.isSafeInteger(sizeBytes)||sizeBytes<1||sizeBytes>ARTIFACT_MAX_BYTES||!SHA.test(sha256||''))throw Error('INVALID_MANIFEST');
   if(typeof idempotencyKey!=='string'||!KEY.test(idempotencyKey))throw Error('INVALID_IDEMPOTENCY_KEY');
   const now=this.#now(),spec=JSON.stringify([sourceDeviceId,targetDeviceId,safeName,sizeBytes,sha256]);
   return this.#store.transaction(()=>{
     const old=this.#store.db.prepare('SELECT d.spec,t.* FROM transfer_dedup d JOIN transfers t ON t.id=d.transfer_id WHERE d.tenant=? AND d.owner=? AND d.idempotency=?')
       .get(actor.tenantId,actor.id,idempotencyKey);
     if(old){if(old.spec!==spec)throw Error('IDEMPOTENCY_CONFLICT');if(old.expires<=now)throw Error('NOT_FOUND_OR_EXPIRED');return this.#summary(old);}
     const grant=this.#approval.verify(approvalProof,now);
     if(grant.tenantId!==actor.tenantId||grant.ownerId!==actor.id||grant.sourceDeviceId!==sourceDeviceId||grant.targetDeviceId!==targetDeviceId||grant.sizeBytes!==sizeBytes||grant.sha256!==sha256)reject();
     const used=this.#store.db.prepare('SELECT 1 FROM approval_nonces WHERE nonce=?').get(grant.nonce);
     if(used)throw Error('APPROVAL_REPLAY');
     const active=this.#store.db.prepare("SELECT COALESCE(SUM(size),0) AS bytes, COUNT(*) AS n FROM transfers WHERE tenant=? AND expires>? AND state IN ('UPLOADING','READY')").get(actor.tenantId,now);
     if(active.bytes+sizeBytes>32*1024*1024||active.n>=16)throw Error('TENANT_QUOTA_EXCEEDED');
     const id=randomUUID(),expires=now+ARTIFACT_TTL_SECONDS;
     this.#store.db.prepare('INSERT INTO approval_nonces(nonce,tenant,expires,kind) VALUES(?,?,?,?)').run(grant.nonce,actor.tenantId,grant.expiresAt,'artifact');
     this.#store.db.prepare('INSERT INTO transfers(id,tenant,owner,src,dst,filename,size,sha,chunks_total,state,created,expires) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
       .run(id,actor.tenantId,actor.id,sourceDeviceId,targetDeviceId,safeName,sizeBytes,sha256,Math.ceil(sizeBytes/ARTIFACT_CHUNK_BYTES),'UPLOADING',now,expires);
     this.#store.db.prepare('INSERT INTO transfer_dedup(tenant,owner,idempotency,spec,transfer_id) VALUES(?,?,?,?,?)')
       .run(actor.tenantId,actor.id,idempotencyKey,spec,id);
     this.#store.audit(actor.tenantId,actor.id,id,'TRANSFER_CREATED',now);
     return this.#summary(this.#store.db.prepare('SELECT * FROM transfers WHERE id=?').get(id));
   });
 }
 status(actor,transferId){return this.#summary(this.#load(actor,transferId));}
 upload({actor,transferId,index,base64,chunkSha256}){
   const rec=this.#load(actor,transferId);
   this.#directory.assertAgent(actor,rec.tenant,rec.src);
   if(rec.state!=='UPLOADING')throw Error('TRANSFER_NOT_WRITABLE');
   if(!Number.isInteger(index)||index<0||index>=rec.chunks_total||!SHA.test(chunkSha256||''))throw Error('INVALID_CHUNK');
   const expected=Math.min(ARTIFACT_CHUNK_BYTES,rec.size-index*ARTIFACT_CHUNK_BYTES);
   if(typeof base64!=='string'||base64.length>Math.ceil(ARTIFACT_CHUNK_BYTES/3)*4+4)throw Error('INVALID_CHUNK');
   const plain=Buffer.from(base64,'base64');
   if(plain.length!==expected||plain.toString('base64')!==base64||!equal(sha(plain),chunkSha256))throw Error('CHUNK_HASH_OR_LENGTH_MISMATCH');
   return this.#store.transaction(()=>{
     const fresh=this.#load(actor,transferId);
     if(fresh.state!=='UPLOADING')throw Error('TRANSFER_NOT_WRITABLE');
     const old=this.#store.db.prepare('SELECT sha,cipher,iv,tag FROM transfer_chunks WHERE transfer_id=? AND idx=?').get(transferId,index);
     const aad=fresh.tenant+'|'+fresh.id+'|'+index;
     if(old){
       if(equal(old.sha,chunkSha256)&&this.#store.decrypt(old,aad).equals(plain))return {state:'ALREADY_PRESENT',index};
       throw Error('CHUNK_REPLAY_CONFLICT');
     }
     const {cipher,iv,tag}=this.#store.encrypt(plain,aad);
     this.#store.db.prepare('INSERT INTO transfer_chunks(transfer_id,idx,sha,cipher,iv,tag) VALUES(?,?,?,?,?,?)')
       .run(transferId,index,chunkSha256,cipher,iv,tag);
     return {state:'STORED',index};
   });
 }
 finalize(actor,transferId){
   const rec=this.#load(actor,transferId);
   this.#directory.assertAgent(actor,rec.tenant,rec.src);
   if(rec.state==='READY'||rec.state==='DELIVERED')return this.#summary(rec);
   if(rec.state!=='UPLOADING')throw Error('TRANSFER_NOT_WRITABLE');
   const result=this.#store.transaction(()=>{
     const fresh=this.#load(actor,transferId);
     if(fresh.state!=='UPLOADING')throw Error('TRANSFER_NOT_WRITABLE');
     const rows=this.#store.db.prepare('SELECT idx,sha,cipher,iv,tag FROM transfer_chunks WHERE transfer_id=? ORDER BY idx').all(transferId);
     if(rows.length!==fresh.chunks_total)throw Error('CHUNKS_MISSING');
     const full=createHash('sha256');let bytes=0;
     for(let i=0;i<rows.length;i++){
       const row=rows[i];if(row.idx!==i)throw Error('CHUNKS_MISSING');
       const plain=this.#store.decrypt(row,fresh.tenant+'|'+fresh.id+'|'+i);
       if(!equal(sha(plain),row.sha))throw Error('STORAGE_INTEGRITY_FAILED');
       bytes+=plain.length;full.update(plain);
     }
     const valid=bytes===fresh.size&&equal(full.digest('hex'),fresh.sha);
     this.#store.db.prepare('UPDATE transfers SET state=? WHERE id=?').run(valid?'READY':'FAILED_INTEGRITY',fresh.id);
     this.#store.audit(fresh.tenant,actor.id,fresh.id,valid?'TRANSFER_READY':'TRANSFER_INTEGRITY_FAILED',this.#now());
     return valid;
   });
   if(!result)throw Error('FULL_HASH_MISMATCH');
   return this.status(actor,transferId);
 }
 download({actor,transferId,index}){
   const rec=this.#load(actor,transferId);
   this.#directory.assertAgent(actor,rec.tenant,rec.dst);
   if(rec.state!=='READY')throw Error('TRANSFER_NOT_READY');
   if(!Number.isInteger(index)||index<0||index>=rec.chunks_total)throw Error('INVALID_CHUNK');
   const row=this.#store.db.prepare('SELECT sha,cipher,iv,tag FROM transfer_chunks WHERE transfer_id=? AND idx=?').get(transferId,index);
   if(!row)throw Error('CHUNKS_MISSING');
   const plain=this.#store.decrypt(row,rec.tenant+'|'+rec.id+'|'+index);
   if(!equal(sha(plain),row.sha))throw Error('STORAGE_INTEGRITY_FAILED');
   return {index,base64:plain.toString('base64'),sha256:row.sha};
 }
 acknowledge({actor,transferId,receivedSha256}){
   const rec=this.#load(actor,transferId);
   this.#directory.assertAgent(actor,rec.tenant,rec.dst);
   if(rec.state==='DELIVERED'&&equal(receivedSha256,rec.sha))return this.#summary(rec);
   if(rec.state!=='READY')throw Error('TRANSFER_NOT_READY');
   if(!equal(receivedSha256,rec.sha))throw Error('DESTINATION_HASH_MISMATCH');
   return this.#store.transaction(()=>{
     this.#store.db.prepare("UPDATE transfers SET state='DELIVERED' WHERE id=? AND state='READY'").run(rec.id);
     this.#store.db.prepare('DELETE FROM transfer_chunks WHERE transfer_id=?').run(rec.id);
     this.#store.audit(rec.tenant,actor.id,rec.id,'TRANSFER_DELIVERED',this.#now());
     return this.status(actor,transferId);
   });
 }
 cancel(actor,transferId){
   this.#directory.assertOwner(actor);
   const rec=this.#load(actor,transferId);
   if(rec.state==='DELIVERED')throw Error('DELIVERED_CANNOT_CANCEL');
   return this.#store.transaction(()=>{
     this.#store.db.prepare("UPDATE transfers SET state='CANCELLED' WHERE id=?").run(rec.id);
     this.#store.db.prepare('DELETE FROM transfer_chunks WHERE transfer_id=?').run(rec.id);
     this.#store.audit(rec.tenant,actor.id,rec.id,'TRANSFER_CANCELLED',this.#now());
     return this.status(actor,transferId);
   });
 }
 sweep(){this.#store.sweep(this.#now());}
}
