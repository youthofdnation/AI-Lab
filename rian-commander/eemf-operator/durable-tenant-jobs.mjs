/**
 * Durable per-tenant, device-bound job queue.
 * Failed/disconnected in-flight jobs become UNKNOWN_DO_NOT_RETRY.
 * Not connected to any production relay, device, or browser owner-approval UI.
 */
import {randomUUID,createHash} from 'node:crypto';
import {TenantDirectory} from './tenant-artifact-core.mjs';
import {TenantJobQueue,OwnerJobApproval,validateJobAction} from './tenant-job-policy.mjs';
import {StagingSqlite} from './staging-sqlite.mjs';
const KEY=/^[A-Za-z0-9_-]{16,80}$/, WRITE=new Set(['write_file','run_command']);
const sha=x=>createHash('sha256').update(x).digest('hex');
const denied=()=>{throw Error('ACCESS_DENIED');};

export class DurableTenantJobQueue extends TenantJobQueue {
 #store;#directory;#approval;#clock;
 constructor({directory,approval,store,clock=()=>Date.now()}){
   super({directory,approval,clock});
   if(!(store instanceof StagingSqlite)||typeof clock!=='function')throw Error('INVALID_DURABLE_JOB_QUEUE');
   this.#store=store;this.#directory=directory;this.#approval=approval;this.#clock=clock;
 }
 #now(){return Math.floor(this.#clock()/1000);}
 #owned(actor,id){
   this.#directory.assertOwner(actor);
   const j=this.#store.db.prepare('SELECT * FROM jobs WHERE id=? AND tenant=?').get(id,actor.tenantId);
   if(!j)throw Error('JOB_NOT_FOUND');
   return j;
 }
 #encrypt(value,aad){return this.#store.encrypt(Buffer.from(JSON.stringify(value),'utf8'),aad);}
 #decrypt(value,aad){
   return JSON.parse(this.#store.decrypt({cipher:value.result_cipher,iv:value.result_iv,tag:value.result_tag},aad).toString('utf8'));
 }
 #summary(j){
   let result=null;
   if(j.result_cipher!==null && j.result_cipher!==undefined)result=this.#decrypt(j,'job-result|'+j.tenant+'|'+j.id);
   return {jobId:j.id,deviceId:j.device,action:j.action,state:j.state,createdAt:j.created,deadline:j.deadline,result};
 }
 enqueue({actor,deviceId,action,args,approvalProof,requestKey}){
   this.#directory.assertOwner(actor);
   this.#directory.assertDevice(actor.tenantId,deviceId);
   if(typeof requestKey!=='string'||!KEY.test(requestKey))throw Error('INVALID_REQUEST_KEY');
   const safe=validateJobAction(action,args);
   const spec=sha(JSON.stringify([deviceId,action,safe]));
   const now=this.#now();
   return this.#store.transaction(()=>{
     const existing=this.#store.db.prepare('SELECT * FROM jobs WHERE tenant=? AND owner=? AND request_key=?').get(actor.tenantId,actor.id,requestKey);
     if(existing){
       if(existing.spec_sha!==spec)throw Error('IDEMPOTENCY_CONFLICT');
       return {jobId:existing.id,state:existing.state};
     }
     const pending=this.#store.db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE tenant=? AND device=? AND state='PENDING' AND deadline>?").get(actor.tenantId,deviceId,now);
     if(pending.n>=3)throw Error('QUEUE_FULL');
     if(WRITE.has(action)){
       const grant=this.#approval.verify(approvalProof,now);
       if(grant.tenantId!==actor.tenantId||grant.ownerId!==actor.id||grant.deviceId!==deviceId||grant.action!==action||grant.argsSha256!==sha(JSON.stringify(safe)))denied();
       if(this.#store.db.prepare('SELECT 1 FROM approval_nonces WHERE nonce=?').get(grant.nonce))throw Error('APPROVAL_REPLAY');
       this.#store.db.prepare('INSERT INTO approval_nonces(nonce,tenant,expires,kind) VALUES(?,?,?,?)').run(grant.nonce,actor.tenantId,grant.expiresAt,'job');
     }
     const id=randomUUID(), deadline=now+180;
     const encrypted=this.#encrypt(safe,'job-args|'+actor.tenantId+'|'+id);
     this.#store.db.prepare('INSERT INTO jobs(id,tenant,owner,request_key,spec_sha,device,action,args_cipher,args_iv,args_tag,state,created,deadline) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)')
       .run(id,actor.tenantId,actor.id,requestKey,spec,deviceId,action,encrypted.cipher,encrypted.iv,encrypted.tag,'PENDING',now,deadline);
     this.#store.audit(actor.tenantId,actor.id,id,'JOB_ENQUEUED',now);
     return {jobId:id,state:'PENDING'};
   });
 }
 poll(actor,deviceId){
   this.#directory.assertAgent(actor,actor.tenantId,deviceId);
   const now=this.#now();
   return this.#store.transaction(()=>{
     this.#store.db.prepare("UPDATE jobs SET state='EXPIRED' WHERE tenant=? AND device=? AND state='PENDING' AND deadline<=?").run(actor.tenantId,deviceId,now);
     const j=this.#store.db.prepare("SELECT * FROM jobs WHERE tenant=? AND device=? AND state='PENDING' AND deadline>? ORDER BY created ASC,id ASC LIMIT 1").get(actor.tenantId,deviceId,now);
     if(!j)return {job:null};
     const leaseUntil=now+120;
     const changed=this.#store.db.prepare("UPDATE jobs SET state='RUNNING',lease_until=? WHERE id=? AND state='PENDING'").run(leaseUntil,j.id);
     if(changed.changes!==1)throw Error('JOB_CLAIM_CONFLICT');
     const args=JSON.parse(this.#store.decrypt({cipher:j.args_cipher,iv:j.args_iv,tag:j.args_tag},'job-args|'+j.tenant+'|'+j.id).toString('utf8'));
     this.#store.audit(j.tenant,actor.id,j.id,'JOB_DISPATCHED',now);
     return {jobId:j.id,action:j.action,args,leaseUntil};
   });
 }
 complete(actor,{jobId,result}){
   this.#directory.assertActor(actor);
   if(!result||typeof result!=='object'||Array.isArray(result)||Object.keys(result).sort().join(',')!=='exitCode,output'||!Number.isInteger(result.exitCode)||typeof result.output!=='string'||Buffer.byteLength(result.output)>100000)throw Error('INVALID_RESULT');
   return this.#store.transaction(()=>{
     const j=this.#store.db.prepare('SELECT * FROM jobs WHERE id=? AND tenant=?').get(jobId,actor.tenantId);
     if(!j)throw Error('JOB_NOT_FOUND');
     this.#directory.assertAgent(actor,j.tenant,j.device);
     if(j.state!=='RUNNING'||j.lease_until<=this.#now())throw Error('JOB_NOT_RUNNING');
     const encrypted=this.#encrypt(result,'job-result|'+j.tenant+'|'+j.id);
     const changed=this.#store.db.prepare("UPDATE jobs SET state='DONE',result_cipher=?,result_iv=?,result_tag=? WHERE id=? AND state='RUNNING'")
       .run(encrypted.cipher,encrypted.iv,encrypted.tag,j.id);
     if(changed.changes!==1)throw Error('JOB_NOT_RUNNING');
     this.#store.audit(j.tenant,actor.id,j.id,'JOB_COMPLETED',this.#now());
     return {jobId:j.id,state:'DONE'};
   });
 }
 get(actor,jobId){return this.#summary(this.#owned(actor,jobId));}
 cancel(actor,jobId){
   const j=this.#owned(actor,jobId);
   if(j.state==='DONE')throw Error('ALREADY_DONE');
   if(['CANCELLED','EXPIRED','UNKNOWN_DO_NOT_RETRY'].includes(j.state))return {jobId:j.id,state:j.state};
   const next=j.state==='RUNNING'?'CANCEL_REQUESTED':'CANCELLED';
   return this.#store.transaction(()=>{
     this.#store.db.prepare('UPDATE jobs SET state=? WHERE id=?').run(next,j.id);
     this.#store.audit(j.tenant,actor.id,j.id,'JOB_'+next,this.#now());
     return {jobId:j.id,state:next};
   });
 }
 reap(){
   const now=this.#now();
   this.#store.transaction(()=>{
     this.#store.db.prepare("UPDATE jobs SET state='EXPIRED' WHERE state='PENDING' AND deadline<=?").run(now);
     this.#store.db.prepare("UPDATE jobs SET state='UNKNOWN_DO_NOT_RETRY' WHERE state IN ('RUNNING','CANCEL_REQUESTED') AND lease_until<=?").run(now);
   });
 }
}
