/** Persistent, owner-approved read policy. Registration never approves a mail sync. */
import {randomUUID} from 'node:crypto';
import {planReadPolicy,readPolicyAllows} from './read-policy-scope.mjs';
import {recentMessageHashes,reviewMessageHash} from './mail-review-scope.mjs';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FOREVER=253402300799;
const REAPPROVAL_SECONDS=86400;

export class ReadPolicyStore {
  #store;#clock;
  constructor(store,clock=()=>Date.now()){this.#store=store;this.#clock=clock;}
  #now(){return Math.floor(this.#clock()/1000);}
  #db(){return this.#store.db;}
  #account(row){return this.#store.decrypt({cipher:row.account_cipher,iv:row.account_iv,tag:row.account_tag},
    'read-policy-account|'+row.tenant+'|'+row.id).toString('utf8');}
  #expire(now){this.#db().prepare("UPDATE read_policies SET state='EXPIRED' WHERE state='ACTIVE' AND expires<=?").run(now);}
  prepare({actor,device,clientRef,scope,replacePolicyId=null}){
    if(!actor||!actor.tenantId||!actor.id||typeof device!=='string'||!device||device.length>128)throw Error('INVALID_POLICY_REQUEST');
    if(typeof clientRef!=='string'||!/^[a-f0-9]{16,64}$/.test(clientRef))throw Error('OAUTH_CLIENT_REQUIRED');
    const p=planReadPolicy(scope),now=this.#now(),id=randomUUID(),featuresJson=JSON.stringify(p.features);
    return this.#store.transaction(()=>{
      if(replacePolicyId===null){
        const active=this.#db().prepare("SELECT * FROM read_policies WHERE tenant=? AND owner=? AND device=? AND client_ref=? AND account_fp=? AND account_type=? AND state='ACTIVE' AND expires>? ORDER BY expires DESC")
          .all(actor.tenantId,actor.id,device,clientRef,p.accountFp,p.accountType,now);
        const existing=active.find(x=>(p.seconds===null?x.expires===FOREVER:x.expires-x.created>=p.seconds)&&x.max_days>=p.maxSyncDays&&
            x.max_messages>=p.maxSyncMessages&&p.features.every(f=>JSON.parse(x.features).includes(f)));
        if(existing)return {grant_id:existing.id,state:'ACTIVE',expires_at:existing.expires===FOREVER?null:existing.expires,
          reused:true};
        if(active.length)replacePolicyId=active[0].id; // a broader request stays pending until fresh owner approval
      }
      const pending=this.#db().prepare("SELECT id,approval_expires,created FROM read_policy_requests WHERE tenant=? AND owner=? AND device=? AND client_ref=? AND account_fp=? AND account_type=? AND features=? AND duration=? AND max_days=? AND max_messages=? AND state='PENDING' AND COALESCE(replace_policy_id,'')=? AND created>? ORDER BY created DESC LIMIT 1")
        .get(actor.tenantId,actor.id,device,clientRef,p.accountFp,p.accountType,featuresJson,p.duration,
          p.maxSyncDays,p.maxSyncMessages,replacePolicyId||'',now-REAPPROVAL_SECONDS);
      if(pending)return {request_id:pending.id,state:pending.approval_expires<=now?'EXPIRED':'PENDING',
        approval_expires_at:pending.approval_expires,renewable_until_at:pending.created+REAPPROVAL_SECONDS,deduplicated:true};
      const enc=this.#store.encrypt(Buffer.from(p.account,'utf8'),'read-policy-account|'+actor.tenantId+'|'+id);
      this.#db().prepare("INSERT INTO read_policy_requests(id,tenant,owner,device,client_ref,account_cipher,account_iv,account_tag,account_fp,account_type,features,duration,max_days,max_messages,created,approval_expires,state,replace_policy_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'PENDING',?)")
        .run(id,actor.tenantId,actor.id,device,clientRef,enc.cipher,enc.iv,enc.tag,p.accountFp,p.accountType,
          featuresJson,p.duration,p.maxSyncDays,p.maxSyncMessages,now,now+900,replacePolicyId);
      this.#store.audit(actor.tenantId,actor.id,id,'READ_POLICY_APPROVAL_REQUESTED',now);
      return {request_id:id,state:'PENDING',approval_expires_at:now+900};
    });
  }
  prepareChange({actor,grantId,scope}){
    if(typeof grantId!=='string'||!UUID.test(grantId))throw Error('GRANT_NOT_FOUND');
    const old=this.#db().prepare("SELECT * FROM read_policies WHERE id=? AND tenant=? AND owner=? AND state='ACTIVE' AND expires>?")
      .get(grantId,actor.tenantId,actor.id,this.#now());
    if(!old)throw Error('GRANT_NOT_FOUND');
    const original=this.#db().prepare('SELECT * FROM read_policy_requests WHERE id=?').get(grantId);
    if(!original)throw Error('POLICY_REQUEST_NOT_FOUND');
    const request=this.prepare({actor,device:old.device,clientRef:old.client_ref,replacePolicyId:grantId,
      scope:{...scope,account:this.#account(original),accountType:old.account_type}});
    this.#store.audit(actor.tenantId,actor.id,request.request_id,'READ_POLICY_CHANGE_REQUESTED',this.#now());
    return request;
  }
  listRequests(actor,limit=50){
    const rows=this.#db().prepare('SELECT id FROM read_policy_requests WHERE tenant=? AND owner=? ORDER BY created DESC LIMIT ?')
      .all(actor.tenantId,actor.id,Math.min(Math.max(Number(limit)||50,1),100));
    return rows.map(x=>this.preview(x.id));
  }
  preview(id){
    if(typeof id!=='string'||!UUID.test(id))throw Error('POLICY_REQUEST_NOT_FOUND');
    const row=this.#db().prepare('SELECT * FROM read_policy_requests WHERE id=?').get(id);
    if(!row)throw Error('POLICY_REQUEST_NOT_FOUND');
    const now=this.#now(),state=row.state==='PENDING'&&row.approval_expires<=now?'EXPIRED':row.state;
    const renewable=row.state==='PENDING'&&now>=row.created&&now<row.created+REAPPROVAL_SECONDS;
    const grant=row.state==='APPROVED'?this.#db().prepare('SELECT id,state,expires,calls_used FROM read_policies WHERE id=?').get(id):null;
    return {request_id:id,tenant:row.tenant,owner:row.owner,device:row.device,client_ref:row.client_ref,
      account:this.#account(row),account_type:row.account_type,features:JSON.parse(row.features),duration:row.duration,
      max_days:row.max_days,max_messages:row.max_messages,state,approval_expires_at:row.approval_expires,
      renewable,renewable_until_at:row.created+REAPPROVAL_SECONDS,replace_policy_id:row.replace_policy_id||null,
      grant:grant?{grant_id:grant.id,state:grant.state==='ACTIVE'&&grant.expires<=now?'EXPIRED':grant.state,
        expires_at:grant.expires===FOREVER?null:grant.expires,calls_used:grant.calls_used}:null};
  }
  approve({id,tenant,owner,scopeOverride=null}){
    const now=this.#now();
    return this.#store.transaction(()=>{
      const row=this.#db().prepare('SELECT * FROM read_policy_requests WHERE id=? AND tenant=? AND owner=?').get(id,tenant,owner);
      if(!row||row.state!=='PENDING'||now<row.created||now>=row.created+REAPPROVAL_SECONDS)throw Error('POLICY_APPROVAL_EXPIRED');
      const renewing=row.approval_expires<=now;
      const requestedFeatures=JSON.parse(row.features);
      const override=scopeOverride||{};
      if(override&&Object.keys(override).some(k=>!['features','duration','maxSyncDays','maxSyncMessages'].includes(k)))throw Error('INVALID_POLICY_SCOPE');
      const p=planReadPolicy({account:this.#account(row),accountType:row.account_type,
        features:override.features??requestedFeatures,duration:override.duration??row.duration,
        maxSyncDays:override.maxSyncDays??row.max_days,maxSyncMessages:override.maxSyncMessages??row.max_messages});
      if(p.features.some(x=>!requestedFeatures.includes(x))||p.maxSyncDays>row.max_days||p.maxSyncMessages>row.max_messages)
        throw Error('POLICY_SCOPE_EXPANDED');
      let old=null;
      if(row.replace_policy_id){
        old=this.#db().prepare("SELECT * FROM read_policies WHERE id=? AND tenant=? AND owner=? AND state='ACTIVE' AND expires>?")
          .get(row.replace_policy_id,tenant,owner,now);
        if(!old||old.device!==row.device||old.client_ref!==row.client_ref||old.account_fp!==row.account_fp)
          throw Error('POLICY_REPLACEMENT_INVALID');
      }
      const duplicate=this.#db().prepare("SELECT id FROM read_policies WHERE tenant=? AND owner=? AND device=? AND client_ref=? AND account_fp=? AND state='ACTIVE' AND expires>? AND id<>?")
        .get(tenant,owner,row.device,row.client_ref,row.account_fp,now,row.replace_policy_id||'');
      if(duplicate)throw Error('READ_POLICY_ALREADY_ACTIVE');
      if(old){
        this.#db().prepare("UPDATE read_policies SET state='REVOKED' WHERE id=?").run(old.id);
        this.#db().prepare("UPDATE long_jobs SET state='CANCELLED',finished=? WHERE state='QUEUED' AND id IN (SELECT job_id FROM read_policy_job_links WHERE policy_id=?)").run(now,old.id);
        this.#db().prepare("UPDATE long_jobs SET state='CANCEL_REQUESTED' WHERE state='RUNNING' AND id IN (SELECT job_id FROM read_policy_job_links WHERE policy_id=?)").run(old.id);
        this.#db().prepare('DELETE FROM read_policy_message_hashes WHERE policy_id=?').run(old.id);
        this.#store.audit(tenant,owner,old.id,'READ_POLICY_REPLACED',now);
      }
      this.#db().prepare("INSERT INTO read_policies(id,tenant,owner,device,client_ref,account_fp,account_type,features,max_days,max_messages,created,expires,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?, 'ACTIVE')")
        .run(id,tenant,owner,row.device,row.client_ref,p.accountFp,p.accountType,JSON.stringify(p.features),p.maxSyncDays,p.maxSyncMessages,
          now,p.seconds===null?FOREVER:now+p.seconds);
      this.#db().prepare("UPDATE read_policy_requests SET state='APPROVED' WHERE id=?").run(id);
      this.#store.audit(tenant,owner,id,'READ_POLICY_APPROVED',now);
      if(renewing)this.#store.audit(tenant,owner,id,'READ_POLICY_APPROVED_AFTER_REQUEST_EXPIRY',now);
      return {grant_id:id,state:'ACTIVE',expires_at:p.seconds===null?null:now+p.seconds,
        calls_used:0,features:p.features,account_type:p.accountType,device:row.device};
    });
  }
  find({actor,device,clientRef,kind,params}){
    const now=this.#now();this.#expire(now);
    const rows=this.#db().prepare("SELECT * FROM read_policies WHERE tenant=? AND owner=? AND device=? AND client_ref=? AND state='ACTIVE' AND expires>? ORDER BY created DESC")
      .all(actor.tenantId,actor.id,device,clientRef,now);
    for(const row of rows){
      const searched=kind==='mail.read'&&!!this.#db().prepare('SELECT 1 FROM read_policy_message_hashes WHERE policy_id=? AND msg_sha=? AND expires>?')
        .get(row.id,reviewMessageHash(params.messageId),now);
      if(readPolicyAllows({...row,features:JSON.parse(row.features),maxSyncDays:row.max_days,maxSyncMessages:row.max_messages},kind,params,{searched}))
        return row;
    }
    return null;
  }
  link(jobId,policy,kind,params){
    this.#db().prepare('INSERT INTO read_policy_job_links(job_id,policy_id) VALUES(?,?)').run(jobId,policy.id);
    this.#db().prepare('UPDATE read_policies SET calls_used=calls_used+1 WHERE id=?').run(policy.id);
    if(kind==='mail.read')this.#db().prepare('DELETE FROM read_policy_message_hashes WHERE policy_id=? AND msg_sha=?')
      .run(policy.id,reviewMessageHash(params.messageId));
    this.#store.audit(policy.tenant,policy.owner,policy.id,'READ_POLICY_JOB_USED',this.#now());
  }
  forJob(jobId){return this.#db().prepare('SELECT p.* FROM read_policy_job_links l JOIN read_policies p ON p.id=l.policy_id WHERE l.job_id=?').get(jobId);}
  recordSearch(policy,output){
    const allowed=new Set(recentMessageHashes(output,{nowSeconds:this.#now(),maxDays:policy.max_days}));
    for(const row of (Array.isArray(output?.results)?output.results.slice(0,20):[])){
      const hash=reviewMessageHash(row?.message_id);
      if(!allowed.has(hash))continue;
      const expires=Math.floor(Date.parse(row.date)/1000)+policy.max_days*86400;
      this.#db().prepare('INSERT INTO read_policy_message_hashes(policy_id,msg_sha,expires) VALUES(?,?,?) ON CONFLICT(policy_id,msg_sha) DO UPDATE SET expires=MAX(expires,excluded.expires)')
        .run(policy.id,hash,expires);
    }
  }
  list(actor){this.#expire(this.#now());return this.#db().prepare("SELECT id,device,account_type,features,created,expires,calls_used,state FROM read_policies WHERE tenant=? AND owner=? AND state='ACTIVE' ORDER BY created DESC")
    .all(actor.tenantId,actor.id).map(x=>({grant_id:x.id,device:x.device,kind:'read.policy',
      account:this.#account(this.#db().prepare('SELECT * FROM read_policy_requests WHERE id=?').get(x.id)),account_type:x.account_type,
      features:JSON.parse(x.features),created_at:x.created,expires_at:x.expires===FOREVER?null:x.expires,
      calls_used:x.calls_used,state:x.state}));}
  revoke(actor,id){
    if(typeof id!=='string'||!UUID.test(id))throw Error('GRANT_NOT_FOUND');
    return this.#store.transaction(()=>{
      const row=this.#db().prepare('SELECT * FROM read_policies WHERE id=? AND tenant=? AND owner=?').get(id,actor.tenantId,actor.id);
      if(!row)throw Error('GRANT_NOT_FOUND');
      const now=this.#now();
      this.#db().prepare("UPDATE read_policies SET state='REVOKED' WHERE id=?").run(id);
      this.#db().prepare("UPDATE long_jobs SET state='CANCELLED',finished=? WHERE state='QUEUED' AND id IN (SELECT job_id FROM read_policy_job_links WHERE policy_id=?)").run(now,id);
      this.#db().prepare("UPDATE long_jobs SET state='CANCEL_REQUESTED' WHERE state='RUNNING' AND id IN (SELECT job_id FROM read_policy_job_links WHERE policy_id=?)").run(id);
      this.#db().prepare('DELETE FROM read_policy_message_hashes WHERE policy_id=?').run(id);
      this.#store.audit(actor.tenantId,actor.id,id,'READ_POLICY_REVOKED',now);
      return {grant_id:id,state:'REVOKED'};
    });
  }
}
