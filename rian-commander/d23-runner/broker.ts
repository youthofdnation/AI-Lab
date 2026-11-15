import { Database } from "bun:sqlite";
import { createHash, createHmac, randomBytes } from "node:crypto";

export const DEVICE = "DESKTOP-1QGT8D6";
export const TASK = "D23_AUDIT_READONLY_V1";
const unix=()=>Math.floor(Date.now()/1000);
const nonce=()=>randomBytes(24).toString("base64url");
function canonical(obj:Record<string,unknown>){return JSON.stringify(Object.fromEntries(Object.entries(obj).sort(([a],[b])=>a.localeCompare(b))))}

export class D23Broker {
 readonly db:Database;
 constructor(path:string,readonly key:string){
  if(key.length<32)throw Error("signing_key_missing");
  this.db=new Database(path,{create:true});
  this.db.exec("PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;");
  if(path!==":memory:")this.db.exec("PRAGMA journal_mode=WAL;");
  this.db.exec("CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,task TEXT NOT NULL,device TEXT NOT NULL,state TEXT NOT NULL,created_at INTEGER NOT NULL,approved_at INTEGER,leased_at INTEGER,expires_at INTEGER,job_nonce TEXT UNIQUE,completed_at INTEGER,result_path TEXT)");
  this.db.exec("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,job_id TEXT NOT NULL,event TEXT NOT NULL,at INTEGER NOT NULL)");
  this.db.exec("CREATE TABLE IF NOT EXISTS enrollment_invites(code_hash TEXT PRIMARY KEY,device TEXT NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,claimed_at INTEGER)");
 }
 event(id:string,evt:string,at:number){this.db.query("INSERT INTO events(job_id,event,at) VALUES(?,?,?)").run(id,evt,at)}
 issueEnrollment(device:string,at=unix()){
  if(device!==DEVICE)throw Error("scope_denied");
  const code=nonce();
  const digest=createHash("sha256").update(code).digest("hex");
  this.db.transaction(()=>{
   this.db.query("UPDATE enrollment_invites SET expires_at=? WHERE device=? AND claimed_at IS NULL AND expires_at>?").run(at-1,device,at);
   this.db.query("INSERT INTO enrollment_invites(code_hash,device,created_at,expires_at) VALUES(?,?,?,?)").run(digest,device,at,at+600);
   this.event("enrollment","invite_issued",at);
  })();
  return {device,enrollment_code:code,expires_at:at+600};
 }
 claimEnrollment(device:string,code:string,at=unix()){
  if(device!==DEVICE||typeof code!=="string"||!/^[A-Za-z0-9_-]{32}$/.test(code))throw Error("enrollment_denied");
  const digest=createHash("sha256").update(code).digest("hex");
  this.db.transaction(()=>{
   const r=this.db.query("UPDATE enrollment_invites SET claimed_at=? WHERE code_hash=? AND device=? AND claimed_at IS NULL AND expires_at>?").run(at,digest,device,at);
   if(r.changes!==1)throw Error("enrollment_denied");
   this.event("enrollment","invite_claimed",at);
  })();
  return {device,registered:true};
 }
 expire(at=unix()){
  this.db.transaction(()=>{
   const stale=this.db.query("SELECT id FROM jobs WHERE (state='PENDING_APPROVAL' AND created_at<?) OR (state='APPROVED' AND approved_at<?) OR (state='LEASED' AND expires_at<?)").all(at-600,at-600,at) as Array<{id:string}>;
   for(const item of stale){
    this.db.query("UPDATE jobs SET state='EXPIRED' WHERE id=?").run(item.id);
    this.event(item.id,"expired",at);
   }
  })();
 }

 request(device:string,task:string,at=unix()){
  if(device!==DEVICE||task!==TASK)throw Error("scope_denied");
  this.expire(at);
  const pending=this.db.query("SELECT count(*) AS n FROM jobs WHERE state IN ('PENDING_APPROVAL','APPROVED','LEASED')").get() as {n:number};
  if(pending.n>=3)throw Error("queue_full");
  const id=nonce();
  this.db.transaction(()=>{this.db.query("INSERT INTO jobs(id,task,device,state,created_at) VALUES(?,?,?,'PENDING_APPROVAL',?)").run(id,task,device,at);this.event(id,"requested",at)})();
  return {job_id:id,state:"PENDING_APPROVAL"};
 }
 approve(id:string,at=unix()){
  if(!/^[A-Za-z0-9_-]{16,64}$/.test(id))throw Error("invalid_id");
  this.db.transaction(()=>{
   const r=this.db.query("UPDATE jobs SET state='APPROVED',approved_at=? WHERE id=? AND state='PENDING_APPROVAL' AND created_at>=?").run(at,id,at-600);
   if(r.changes!==1)throw Error("not_approvable");this.event(id,"approved",at);
  })();return {job_id:id,state:"APPROVED"};
 }
 lease(at=unix()){
  this.expire(at);
  return this.db.transaction(()=>{
   const job=this.db.query("SELECT id FROM jobs WHERE state='APPROVED' AND approved_at>=? ORDER BY approved_at,id LIMIT 1").get(at-600) as {id:string}|null;
   if(!job)return null;
   const idNonce=nonce(),payload={device:DEVICE,task:TASK,issued_at:at,expires_at:at+240,nonce:idNonce};
   const mac=createHmac("sha256",this.key).update(canonical(payload)).digest("hex");
   const updated=this.db.query("UPDATE jobs SET state='LEASED',leased_at=?,expires_at=?,job_nonce=? WHERE id=? AND state='APPROVED'").run(at,at+240,idNonce,job.id);
   if(updated.changes!==1)throw Error("already_leased");
   this.event(job.id,"leased",at);return {job_id:job.id,manifest:{payload,mac}};
  })();
 }
 complete(id:string,requestNonce:string,resultPath:string,at=unix()){
  if(!/^[A-Za-z0-9_-]{16,64}$/.test(id)||!/^status-\d{8}-\d{6}-[a-f0-9]{8}\.json$/.test(resultPath)||!/^[A-Za-z0-9_-]{16,64}$/.test(requestNonce))throw Error("invalid_completion");
  this.db.transaction(()=>{
   const r=this.db.query("UPDATE jobs SET state='COMPLETE',completed_at=?,result_path=? WHERE id=? AND state='LEASED' AND job_nonce=? AND expires_at>=?").run(at,resultPath,id,requestNonce,at);
   if(r.changes!==1)throw Error("not_completable");
   this.event(id,"completed",at);
  })();return {job_id:id,state:"COMPLETE"};
 }
 inspect(id:string){
  if(!/^[A-Za-z0-9_-]{16,64}$/.test(id))throw Error("invalid_id");
  const j=this.db.query("SELECT id,task,device,state,created_at,approved_at,leased_at,completed_at,result_path FROM jobs WHERE id=?").get(id);
  if(!j)throw Error("not_found");return j;
 }
 close(){this.db.close()}
}
