/**
 * RIAN Commander V2 durable long-running job queue (staging service only).
 *
 * Replaces the legacy Relay's ~28 second synchronous wait (112 x 250 ms) with:
 *   request -> job_id immediately -> owner approval (browser, password) or an
 *   exact-scope standing grant -> agent claim with a secret lease token ->
 *   heartbeats with bounded progress -> encrypted result stored durably.
 *
 * Safety properties
 *  - Tenant/owner/device scoped through TenantDirectory; other tenants get
 *    JOB_NOT_FOUND, never a hint that a job exists.
 *  - A job is dispatched at most once. It is never re-queued after a claim, a
 *    restart, a lease loss or a failure. Lost leases become UNKNOWN_DO_NOT_RETRY.
 *  - A server restart keeps RUNNING jobs RUNNING and grants the agent a short
 *    grace period, so a 15 minute mail sync survives a redeploy and its result is
 *    still collected. Only the holder of the lease token can report progress or
 *    the result, so a duplicate or stale agent cannot complete someone else's run.
 *  - Duplicate prevention: per-owner request keys, plus one active job per
 *    (tenant, device, lock group) - e.g. only one mail index sync at a time.
 *  - Approvals expire, can be cancelled, and standing grants are bound to the
 *    exact (device, kind, canonical params) hash with a run and time budget.
 *  - Params and results are AES-256-GCM encrypted at rest (StagingSqlite).
 *    Audit rows hold IDs and event names only.
 */
import {randomUUID,randomBytes,createHash,timingSafeEqual} from 'node:crypto';
import {TenantDirectory} from './tenant-artifact-core.mjs';
import {StagingSqlite} from './staging-sqlite.mjs';
import {LongJobKinds} from './long-job-kinds.mjs';

const KEY=/^[A-Za-z0-9_-]{16,80}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const STAGE=/^[a-z][a-z0-9_]{0,31}$/;
const sha=x=>createHash('sha256').update(x).digest('hex');
const ACTIVE=['AWAITING_APPROVAL','QUEUED','RUNNING','CANCEL_REQUESTED'];
const RUNNING=['RUNNING','CANCEL_REQUESTED'];
const OUTCOMES={SUCCEEDED:'SUCCEEDED',FAILED:'FAILED',CANCELLED:'CANCELLED',TIMED_OUT:'TIMED_OUT',INTERRUPTED:'INTERRUPTED'};
const TERMINAL=new Set(['SUCCEEDED','FAILED','CANCELLED','TIMED_OUT','INTERRUPTED','APPROVAL_CANCELLED','APPROVAL_EXPIRED','EXPIRED','UNKNOWN_DO_NOT_RETRY']);
export const LONG_JOB_LIMITS=Object.freeze({approvalTtlSeconds:900,queueTtlSeconds:21600,bootGraceSeconds:180,maxOpenPerDevice:5,maxResultBytes:100000,onlineSeconds:60,lateResultSeconds:86400,grantMaxMinutes:1440,grantMaxRuns:50});
const placeholder=(n)=>Array(n).fill('?').join(',');

/** Korean guidance shown to ChatGPT so it never asks the user to rerun PowerShell or to retry blindly. */
export function longJobGuidance(state){
  return ({
    AWAITING_APPROVAL:'소유자 승인 대기 중입니다. approval_url을 브라우저에서 열어 정확한 범위를 확인하고 승인하세요. 아직 아무것도 실행되지 않았습니다.',
    QUEUED:'승인 완료, PC 에이전트가 가져가기를 기다리는 중입니다. PC가 꺼져 있으면 켜지는 즉시 실행됩니다.',
    RUNNING:'PC에서 실행 중입니다. 진행률은 job_status로 확인하세요. 같은 작업을 다시 요청하지 마세요.',
    CANCEL_REQUESTED:'취소를 요청했습니다. PC 에이전트가 안전한 지점에서 중단하면 CANCELLED로 바뀝니다.',
    SUCCEEDED:'완료되었습니다. result에 결과가 있습니다.',
    FAILED:'PC에서 실패로 끝났습니다. result의 오류 코드를 확인하세요. 자동 재시도하지 않습니다.',
    CANCELLED:'취소되었습니다.',
    TIMED_OUT:'승인된 최대 실행 시간을 넘겨 PC에서 중단했습니다.',
    INTERRUPTED:'PC 에이전트가 재시작되는 동안 실행 프로세스가 끝나 결과를 확인할 수 없습니다. 중복 위험이 없는지 확인한 뒤 새로 요청하세요.',
    APPROVAL_CANCELLED:'승인 요청이 취소되었습니다. 실행되지 않았습니다.',
    APPROVAL_EXPIRED:'승인 요청이 만료되었습니다. 실행되지 않았습니다.',
    EXPIRED:'승인 후 PC가 정해진 시간 안에 작업을 가져가지 않아 만료되었습니다. 실행되지 않았습니다.',
    UNKNOWN_DO_NOT_RETRY:'PC와의 연결이 끊겨 실행 여부를 알 수 없습니다. 같은 작업을 자동 재시도하지 마세요. 늦게 도착한 결과는 자동으로 반영됩니다.'
  })[state]||'상태를 확인할 수 없습니다.';
}

export class LongJobQueue {
  #store;#directory;#kinds;#clock;#limits;
  constructor({directory,store,kinds=new LongJobKinds(),clock=()=>Date.now(),limits={}}){
    if(!(directory instanceof TenantDirectory)||!(store instanceof StagingSqlite)||!(kinds instanceof LongJobKinds)||typeof clock!=='function')throw Error('INVALID_LONG_JOB_QUEUE');
    this.#store=store;this.#directory=directory;this.#kinds=kinds;this.#clock=clock;
    this.#limits=Object.freeze({...LONG_JOB_LIMITS,...limits});
  }
  get kinds(){return this.#kinds;}
  get limits(){return this.#limits;}
  #now(){return Math.floor(this.#clock()/1000);}
  #db(){return this.#store.db;}
  #aad(kind,j){return 'long-job-'+kind+'|'+j.tenant+'|'+j.id;}
  #params(j){return JSON.parse(this.#store.decrypt({cipher:j.params_cipher,iv:j.params_iv,tag:j.params_tag},this.#aad('params',j)).toString('utf8'));}
  #result(j){
    if(j.result_cipher===null||j.result_cipher===undefined)return null;
    return JSON.parse(this.#store.decrypt({cipher:j.result_cipher,iv:j.result_iv,tag:j.result_tag},this.#aad('result',j)).toString('utf8'));
  }
  #audit(j,actorId,event){this.#store.audit(j.tenant,actorId,j.id,event,this.#now());}
  #row(id){return this.#db().prepare('SELECT * FROM long_jobs WHERE id=?').get(id);}
  #ownedRow(actor,jobId){
    this.#directory.assertOwner(actor);
    if(typeof jobId!=='string'||!UUID.test(jobId))throw Error('JOB_NOT_FOUND');
    const j=this.#db().prepare('SELECT * FROM long_jobs WHERE id=? AND tenant=?').get(jobId,actor.tenantId);
    if(!j)throw Error('JOB_NOT_FOUND');
    return j;
  }
  #agentRow(actor,jobId){
    this.#directory.assertActor(actor);
    if(actor.kind!=='agent'||typeof jobId!=='string'||!UUID.test(jobId))throw Error('JOB_NOT_FOUND');
    const j=this.#db().prepare('SELECT * FROM long_jobs WHERE id=? AND tenant=? AND device=?').get(jobId,actor.tenantId,actor.deviceId);
    if(!j)throw Error('JOB_NOT_FOUND');
    return j;
  }
  #leaseOK(j,token){
    if(typeof token!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(token)||typeof j.lease_sha!=='string')return false;
    return timingSafeEqual(Buffer.from(sha(token),'hex'),Buffer.from(j.lease_sha,'hex'));
  }
  #summary(j,{withResult=true}={}){
    const terminal=TERMINAL.has(j.state);
    let params=null;try{params=this.#params(j);}catch{params=null;}
    const kind=(()=>{try{return this.#kinds.get(j.kind);}catch{return null;}})();
    return {job_id:j.id,device:j.device,kind:j.kind,label:kind?.label||j.kind,params,state:j.state,terminal,
      created_at:j.created,approval_expires_at:j.state==='AWAITING_APPROVAL'?j.approval_expires:null,
      approved_at:j.approved_at,started_at:j.started,heartbeat_at:j.heartbeat_at,finished_at:j.finished,
      run_deadline:j.run_deadline,via_standing_grant:!!j.grant_id,
      progress:j.progress_pct===null&&j.progress_stage===null?null:{percent:j.progress_pct,stage:j.progress_stage,done:j.progress_done,total:j.progress_total},
      outcome:j.outcome,exit_code:j.exit_code,
      result:withResult&&terminal?this.#result(j):null,
      retry_automatically:false,guidance:longJobGuidance(j.state)};
  }
  #reapLocked(now,where='',args=[]){
    const db=this.#db(),changed=[];
    const rows=db.prepare("SELECT id,tenant,state FROM long_jobs WHERE ((state='AWAITING_APPROVAL' AND approval_expires<=?) OR (state='QUEUED' AND queue_deadline<=?) OR (state IN ('RUNNING','CANCEL_REQUESTED') AND lease_until<=?))"+where).all(now,now,now,...args);
    for(const r of rows){
      const next=r.state==='AWAITING_APPROVAL'?'APPROVAL_EXPIRED':r.state==='QUEUED'?'EXPIRED':'UNKNOWN_DO_NOT_RETRY';
      const done=db.prepare('UPDATE long_jobs SET state=?,finished=?,lease_sha=CASE WHEN ?=\'UNKNOWN_DO_NOT_RETRY\' THEN lease_sha ELSE NULL END WHERE id=? AND state=?').run(next,now,next,r.id,r.state);
      if(done.changes===1){this.#store.audit(r.tenant,'system',r.id,'LONG_JOB_'+next,now);changed.push(r.id);}
    }
    db.prepare("UPDATE long_job_grants SET state='EXPIRED' WHERE state='ACTIVE' AND expires<=?").run(now);
    return changed.length;
  }
  reap(){const now=this.#now();return this.#store.transaction(()=>this.#reapLocked(now));}
  /** Called once at service boot. Never re-queues: only extends the lease of in-flight runs by a grace period. */
  recoverAfterRestart(){
    const now=this.#now(),grace=this.#limits.bootGraceSeconds;
    return this.#store.transaction(()=>{
      const rows=this.#db().prepare(`SELECT id,tenant,lease_until FROM long_jobs WHERE state IN (${placeholder(RUNNING.length)})`).all(...RUNNING);
      for(const r of rows){
        this.#db().prepare('UPDATE long_jobs SET lease_until=? WHERE id=?').run(Math.max(r.lease_until||0,now+grace),r.id);
        this.#store.audit(r.tenant,'system',r.id,'LONG_JOB_LEASE_RESTART_GRACE',now);
      }
      return {runningPreserved:rows.length,expired:this.#reapLocked(now)};
    });
  }
  devices(actor){
    const own=this.#directory.listOwnDevices(actor),now=this.#now();
    const seen=new Map(this.#db().prepare('SELECT device,seen FROM agent_seen WHERE tenant=?').all(actor.tenantId).map(x=>[x.device,x.seen]));
    return own.map(d=>({device:d.id,online:(seen.get(d.id)||0)>now-this.#limits.onlineSeconds,last_seen:seen.get(d.id)||null}));
  }
  /** Owner request. Returns immediately with a job id; never waits for execution. */
  request({actor,deviceId,kind,params,requestKey,clientRef=null}){
    this.#directory.assertOwner(actor);
    this.#directory.assertDevice(actor.tenantId,deviceId);
    if(requestKey!==undefined&&requestKey!==null&&(typeof requestKey!=='string'||!KEY.test(requestKey)))throw Error('INVALID_REQUEST_KEY');
    if(clientRef!==null&&(typeof clientRef!=='string'||!/^[a-f0-9]{16,64}$/.test(clientRef)))throw Error('INVALID_CLIENT_REF');
    const {kind:spec,params:safe,specSha}=this.#kinds.canonical(deviceId,kind,params);
    const now=this.#now(),db=this.#db();
    return this.#store.transaction(()=>{
      this.#reapLocked(now,' AND tenant=? AND device=?',[actor.tenantId,deviceId]);
      if(requestKey){
        const old=db.prepare('SELECT * FROM long_jobs WHERE tenant=? AND owner=? AND request_key=?').get(actor.tenantId,actor.id,requestKey);
        if(old){
          if(old.spec_sha!==specSha)throw Error('IDEMPOTENCY_CONFLICT');
          return {...this.#summary(old,{withResult:false}),deduplicated:true};
        }
      }
      const active=spec.lockGroup
        ?db.prepare(`SELECT * FROM long_jobs WHERE tenant=? AND device=? AND lock_group=? AND state IN (${placeholder(ACTIVE.length)}) ORDER BY created LIMIT 1`).get(actor.tenantId,deviceId,spec.lockGroup,...ACTIVE)
        :db.prepare(`SELECT * FROM long_jobs WHERE tenant=? AND device=? AND spec_sha=? AND state IN (${placeholder(ACTIVE.length)}) ORDER BY created LIMIT 1`).get(actor.tenantId,deviceId,specSha,...ACTIVE);
      if(active){
        if(active.spec_sha===specSha)return {...this.#summary(active,{withResult:false}),deduplicated:true};
        throw Error('ACTIVE_JOB_CONFLICT:'+active.id);
      }
      const open=db.prepare(`SELECT COUNT(*) AS n FROM long_jobs WHERE tenant=? AND device=? AND state IN (${placeholder(ACTIVE.length)})`).get(actor.tenantId,deviceId,...ACTIVE).n;
      if(open>=this.#limits.maxOpenPerDevice)throw Error('QUEUE_FULL');
      const id=randomUUID();
      const grant=spec.grantable?db.prepare("SELECT * FROM long_job_grants WHERE tenant=? AND owner=? AND device=? AND kind=? AND spec_sha=? AND state='ACTIVE' AND expires>? AND runs_left>0 ORDER BY expires LIMIT 1")
        .get(actor.tenantId,actor.id,deviceId,kind,specSha,now):null;
      const row={id,tenant:actor.tenantId};
      const enc=this.#store.encrypt(Buffer.from(JSON.stringify(safe),'utf8'),this.#aad('params',row));
      const state=grant?'QUEUED':'AWAITING_APPROVAL';
      db.prepare('INSERT INTO long_jobs(id,tenant,owner,client_ref,request_key,spec_sha,device,kind,lock_group,params_cipher,params_iv,params_tag,state,grant_id,created,approval_expires,queue_deadline,approved_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
        .run(id,actor.tenantId,actor.id,clientRef,requestKey||null,specSha,deviceId,kind,spec.lockGroup,enc.cipher,enc.iv,enc.tag,state,grant?grant.id:null,now,
          grant?null:now+this.#limits.approvalTtlSeconds,grant?now+this.#limits.queueTtlSeconds:null,grant?now:null);
      if(grant){
        const left=grant.runs_left-1;
        db.prepare("UPDATE long_job_grants SET runs_left=?,state=? WHERE id=?").run(left,left>0?'ACTIVE':'EXHAUSTED',grant.id);
        this.#store.audit(actor.tenantId,actor.id,grant.id,'LONG_JOB_GRANT_USED',now);
      }
      this.#store.audit(actor.tenantId,actor.id,id,grant?'LONG_JOB_QUEUED_BY_GRANT':'LONG_JOB_AWAITING_APPROVAL',now);
      return {...this.#summary(this.#row(id),{withResult:false}),deduplicated:false,approval_required:!grant};
    });
  }
  /** Unauthenticated approval page preview: the job id is an unguessable UUID shown only to its owner. */
  approvalPreview(jobId){
    if(typeof jobId!=='string'||!UUID.test(jobId))throw Error('JOB_NOT_FOUND');
    const j=this.#row(jobId);
    if(!j)throw Error('JOB_NOT_FOUND');
    const now=this.#now();
    if(j.state==='AWAITING_APPROVAL'&&j.approval_expires<=now){this.reap();return this.approvalPreview(jobId);}
    const kind=this.#kinds.get(j.kind),params=this.#params(j);
    return {jobId:j.id,tenantId:j.tenant,ownerId:j.owner,device:j.device,kind:j.kind,label:kind.label,lines:kind.describe(params),params,
      state:j.state,approvalExpiresAt:j.approval_expires,maxRuntimeSeconds:kind.maxRuntimeSeconds,grantable:kind.grantable,lockGroup:kind.lockGroup};
  }
  /**
   * The approval HTTP handler calls this only after verifying the tenant owner's
   * password. `approver` is {tenantId, ownerId} from that verification, never from the request body.
   */
  approve({approver,jobId,grant=null}){
    if(!approver||typeof approver.tenantId!=='string'||typeof approver.ownerId!=='string')throw Error('ACCESS_DENIED');
    const now=this.#now(),db=this.#db();
    return this.#store.transaction(()=>{
      this.#reapLocked(now);
      const j=typeof jobId==='string'&&UUID.test(jobId)?this.#row(jobId):null;
      if(!j||j.tenant!==approver.tenantId||j.owner!==approver.ownerId)throw Error('JOB_NOT_FOUND');
      if(j.state!=='AWAITING_APPROVAL')throw Error('APPROVAL_NOT_PENDING');
      const kind=this.#kinds.get(j.kind);
      let grantId=null;
      if(grant!==null){
        if(!kind.grantable)throw Error('GRANT_NOT_ALLOWED_FOR_KIND');
        const {minutes,maxRuns}=grant;
        if(!Number.isInteger(minutes)||minutes<1||minutes>this.#limits.grantMaxMinutes||!Number.isInteger(maxRuns)||maxRuns<1||maxRuns>this.#limits.grantMaxRuns)throw Error('INVALID_GRANT');
        const dup=db.prepare("SELECT id FROM long_job_grants WHERE tenant=? AND owner=? AND device=? AND kind=? AND spec_sha=? AND state='ACTIVE' AND expires>?").get(j.tenant,j.owner,j.device,j.kind,j.spec_sha,now);
        if(dup)throw Error('GRANT_ALREADY_ACTIVE');
        grantId=randomUUID();
        db.prepare("INSERT INTO long_job_grants(id,tenant,owner,device,kind,spec_sha,created,expires,runs_left,state) VALUES(?,?,?,?,?,?,?,?,?,'ACTIVE')")
          .run(grantId,j.tenant,j.owner,j.device,j.kind,j.spec_sha,now,now+minutes*60,maxRuns);
        this.#store.audit(j.tenant,approver.ownerId,grantId,'LONG_JOB_GRANT_CREATED',now);
      }
      const changed=db.prepare("UPDATE long_jobs SET state='QUEUED',approved_at=?,queue_deadline=?,approval_expires=NULL WHERE id=? AND state='AWAITING_APPROVAL'").run(now,now+this.#limits.queueTtlSeconds,j.id);
      if(changed.changes!==1)throw Error('APPROVAL_NOT_PENDING');
      this.#audit(j,approver.ownerId,'LONG_JOB_APPROVED');
      return {jobId:j.id,state:'QUEUED',grantId};
    });
  }
  cancel({actor,jobId}){
    const j=this.#ownedRow(actor,jobId),now=this.#now();
    if(TERMINAL.has(j.state))return this.#summary(j,{withResult:false});
    const next=j.state==='AWAITING_APPROVAL'?'APPROVAL_CANCELLED':j.state==='QUEUED'?'CANCELLED':'CANCEL_REQUESTED';
    return this.#store.transaction(()=>{
      const done=this.#db().prepare('UPDATE long_jobs SET state=?,finished=CASE WHEN ?=\'CANCEL_REQUESTED\' THEN NULL ELSE ? END WHERE id=? AND state=?').run(next,next,now,j.id,j.state);
      if(done.changes!==1)throw Error('JOB_STATE_CHANGED');
      this.#audit(j,actor.id,'LONG_JOB_'+next);
      return this.#summary(this.#row(j.id),{withResult:false});
    });
  }
  get({actor,jobId}){
    this.reap();
    return this.#summary(this.#ownedRow(actor,jobId));
  }
  list({actor,limit=10}){
    this.#directory.assertOwner(actor);
    if(!Number.isInteger(limit)||limit<1||limit>50)throw Error('INVALID_LIMIT');
    this.reap();
    return this.#db().prepare('SELECT * FROM long_jobs WHERE tenant=? ORDER BY created DESC,rowid DESC LIMIT ?').all(actor.tenantId,limit).map(j=>this.#summary(j,{withResult:false}));
  }
  listGrants(actor){
    this.#directory.assertOwner(actor);
    this.reap();
    return this.#db().prepare("SELECT id,device,kind,created,expires,runs_left,state FROM long_job_grants WHERE tenant=? AND owner=? AND state='ACTIVE' ORDER BY expires").all(actor.tenantId,actor.id)
      .map(g=>({grant_id:g.id,device:g.device,kind:g.kind,created_at:g.created,expires_at:g.expires,runs_left:g.runs_left,state:g.state}));
  }
  revokeGrant({actor,grantId}){
    this.#directory.assertOwner(actor);
    if(typeof grantId!=='string'||!UUID.test(grantId))throw Error('GRANT_NOT_FOUND');
    return this.#store.transaction(()=>{
      const g=this.#db().prepare('SELECT * FROM long_job_grants WHERE id=? AND tenant=? AND owner=?').get(grantId,actor.tenantId,actor.id);
      if(!g)throw Error('GRANT_NOT_FOUND');
      this.#db().prepare("UPDATE long_job_grants SET state='REVOKED',runs_left=0 WHERE id=?").run(g.id);
      this.#store.audit(g.tenant,actor.id,g.id,'LONG_JOB_GRANT_REVOKED',this.#now());
      return {grant_id:g.id,state:'REVOKED'};
    });
  }
  /** Agent claims the oldest approved job for its own device. Exactly-once dispatch. */
  claim({actor,deviceId}){
    this.#directory.assertAgent(actor,actor.tenantId,deviceId);
    const now=this.#now(),db=this.#db();
    return this.#store.transaction(()=>{
      db.prepare('INSERT INTO agent_seen(tenant,device,seen) VALUES(?,?,?) ON CONFLICT(tenant,device) DO UPDATE SET seen=excluded.seen').run(actor.tenantId,deviceId,now);
      this.#reapLocked(now,' AND tenant=? AND device=?',[actor.tenantId,deviceId]);
      const j=db.prepare("SELECT * FROM long_jobs WHERE tenant=? AND device=? AND state='QUEUED' AND queue_deadline>? ORDER BY approved_at ASC,created ASC LIMIT 1").get(actor.tenantId,deviceId,now);
      if(!j)return {job:null};
      const kind=this.#kinds.get(j.kind),token=randomBytes(32).toString('base64url');
      const changed=db.prepare("UPDATE long_jobs SET state='RUNNING',started=?,run_deadline=?,lease_sha=?,lease_until=?,heartbeat_at=? WHERE id=? AND state='QUEUED'")
        .run(now,now+kind.maxRuntimeSeconds,sha(token),now+kind.leaseSeconds,now,j.id);
      if(changed.changes!==1)throw Error('JOB_CLAIM_CONFLICT');
      this.#audit(j,actor.id,'LONG_JOB_DISPATCHED');
      return {job:{jobId:j.id,kind:j.kind,params:this.#params(j),leaseToken:token,leaseSeconds:kind.leaseSeconds,maxRuntimeSeconds:kind.maxRuntimeSeconds,runDeadline:now+kind.maxRuntimeSeconds}};
    });
  }
  heartbeat({actor,jobId,leaseToken,progress={}}){
    const now=this.#now();
    if(!progress||typeof progress!=='object'||Array.isArray(progress)||Object.keys(progress).some(k=>!['percent','stage','done','total'].includes(k)))throw Error('INVALID_PROGRESS');
    const {percent=null,stage=null,done=null,total=null}=progress;
    if(percent!==null&&(!Number.isInteger(percent)||percent<0||percent>100))throw Error('INVALID_PROGRESS');
    if(stage!==null&&(typeof stage!=='string'||!STAGE.test(stage)))throw Error('INVALID_PROGRESS');
    for(const n of [done,total])if(n!==null&&(!Number.isInteger(n)||n<0||n>10_000_000))throw Error('INVALID_PROGRESS');
    return this.#store.transaction(()=>{
      const j=this.#agentRow(actor,jobId);
      if(!this.#leaseOK(j,leaseToken))throw Error('LEASE_MISMATCH');
      if(!RUNNING.includes(j.state))return {state:j.state,cancel:true,reason:'NOT_RUNNING'};
      if(j.lease_until<=now)throw Error('LEASE_EXPIRED');
      const kind=this.#kinds.get(j.kind);
      const overtime=now>=j.run_deadline;
      this.#db().prepare('UPDATE long_jobs SET heartbeat_at=?,lease_until=?,progress_pct=COALESCE(?,progress_pct),progress_stage=COALESCE(?,progress_stage),progress_done=COALESCE(?,progress_done),progress_total=COALESCE(?,progress_total) WHERE id=?')
        .run(now,Math.min(now+kind.leaseSeconds,j.run_deadline+kind.leaseSeconds),percent,stage,done,total,j.id);
      this.#db().prepare('INSERT INTO agent_seen(tenant,device,seen) VALUES(?,?,?) ON CONFLICT(tenant,device) DO UPDATE SET seen=excluded.seen').run(j.tenant,j.device,now);
      const cancel=j.state==='CANCEL_REQUESTED'||overtime;
      return {state:j.state,cancel,reason:j.state==='CANCEL_REQUESTED'?'OWNER_CANCELLED':overtime?'MAX_RUNTIME':null};
    });
  }
  /**
   * Agent reports the final outcome. Idempotent for the same lease + result so
   * an agent can safely resend after a network failure or a server restart.
   * A late but authentic result also resolves UNKNOWN_DO_NOT_RETRY.
   */
  complete({actor,jobId,leaseToken,outcome,exitCode,output}){
    if(!Object.hasOwn(OUTCOMES,outcome))throw Error('INVALID_RESULT');
    if(!Number.isInteger(exitCode)||exitCode<-1||exitCode>255||typeof output!=='string'||Buffer.byteLength(output,'utf8')>this.#limits.maxResultBytes)throw Error('INVALID_RESULT');
    const now=this.#now(),resultSha=sha(JSON.stringify([outcome,exitCode,output]));
    return this.#store.transaction(()=>{
      const j=this.#agentRow(actor,jobId);
      if(!this.#leaseOK(j,leaseToken))throw Error('LEASE_MISMATCH');
      if(TERMINAL.has(j.state)&&j.state!=='UNKNOWN_DO_NOT_RETRY'){
        if(j.result_sha===resultSha)return {jobId:j.id,state:j.state,duplicate:true};
        throw Error('JOB_ALREADY_FINISHED');
      }
      if(j.state==='UNKNOWN_DO_NOT_RETRY'&&now>(j.finished||now)+this.#limits.lateResultSeconds)throw Error('LATE_RESULT_REJECTED');
      if(!RUNNING.includes(j.state)&&j.state!=='UNKNOWN_DO_NOT_RETRY')throw Error('JOB_NOT_RUNNING');
      let parsed=output;try{parsed=JSON.parse(output);}catch{}
      const enc=this.#store.encrypt(Buffer.from(JSON.stringify(parsed),'utf8'),this.#aad('result',j));
      const late=j.state==='UNKNOWN_DO_NOT_RETRY';
      this.#db().prepare('UPDATE long_jobs SET state=?,outcome=?,exit_code=?,finished=?,result_sha=?,result_cipher=?,result_iv=?,result_tag=?,progress_pct=CASE WHEN ?=\'SUCCEEDED\' THEN 100 ELSE progress_pct END WHERE id=?')
        .run(outcome,outcome,exitCode,now,resultSha,enc.cipher,enc.iv,enc.tag,outcome,j.id);
      this.#audit(j,actor.id,late?'LONG_JOB_LATE_RESULT_ACCEPTED':'LONG_JOB_'+outcome);
      return {jobId:j.id,state:outcome,duplicate:false,late};
    });
  }
}
