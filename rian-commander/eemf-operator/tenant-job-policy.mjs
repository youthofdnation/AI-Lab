/** Source-only tenant boundary for Relay command jobs. NOT attached to production. */
import {createHash,createHmac,randomUUID,timingSafeEqual} from 'node:crypto';
import {TenantDirectory} from './tenant-artifact-core.mjs';
const READ=new Set(['status','list_directory','read_file']);
const PRIV=new Set(['write_file','run_command']);
const HEX=/^[a-f0-9]{64}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const deny=()=>{throw new Error('ACCESS_DENIED')};
const sha=x=>createHash('sha256').update(x).digest('hex');
function limitedPath(path) {
  if (typeof path!=='string'||!path.trim()||path.length>512||/[\x00-\x1f]/.test(path)) throw new Error('INVALID_PATH');
  const normal=path.replaceAll('\\','/');
  const parts=normal.toLowerCase().split('/');
  const forbidden=['.ssh','.aws','.gnupg','.git','.kube','.config','.codex','.claude','appdata','credentials','secrets','.env','token.json','config.json'];
  if(normal.startsWith('/')||normal.startsWith('~')||normal.includes(':')||parts.some(p=>p==='..'||forbidden.includes(p)||p.startsWith('.env.')||/\.(p12|pfx|pem|key)$/.test(p))) throw new Error('INVALID_PATH');
  return normal;
}
function exact(raw,allowed,required) {
  if(!raw||typeof raw!=='object'||Array.isArray(raw)||Object.keys(raw).some(k=>!allowed.includes(k))||required.some(k=>!Object.hasOwn(raw,k)))throw new Error('INVALID_ARGS');
}
export function validateJobAction(action,args) {
  if (!READ.has(action)&&!PRIV.has(action)) throw new Error('INVALID_ACTION');
  if(action==='status'){exact(args,[],[]);return {};}
  if(action==='list_directory'||action==='read_file'){exact(args,['path'],['path']);return {path:limitedPath(args.path)};}
  if(action==='write_file'){
    exact(args,['path','content','overwrite'],['path','content']);
    if(typeof args.content!=='string'||Buffer.byteLength(args.content)>12000||args.content.includes('\0')||args.overwrite!==undefined&&typeof args.overwrite!=='boolean')throw new Error('INVALID_ARGS');
    return {path:limitedPath(args.path),content:args.content,overwrite:args.overwrite===true};
  }
  exact(args,['argv','cwd','timeout'],['argv']);
  if(!Array.isArray(args.argv)||args.argv.length<1||args.argv.length>20||args.argv.some(x=>typeof x!=='string'||!x.trim()||x.length>500||/[\x00-\x1f]/.test(x)))throw new Error('INVALID_ARGS');
  if(args.cwd!==undefined&&typeof args.cwd!=='string')throw new Error('INVALID_ARGS');
  if(args.timeout!==undefined&&(!Number.isInteger(args.timeout)||args.timeout<1||args.timeout>90))throw new Error('INVALID_ARGS');
  return {argv:[...args.argv],cwd:args.cwd?limitedPath(args.cwd):undefined,timeout:args.timeout||30};
}
export class OwnerJobApproval {
  #secret;
  constructor(secret){if(typeof secret!=='string'||Buffer.byteLength(secret)<48)throw new Error('INVALID_SECRET');this.#secret=secret;}
  issue(claim){
    if(!claim||Object.keys(claim).sort().join(',')!=='action,argsSha256,deviceId,expiresAt,nonce,ownerId,tenantId'||!HEX.test(claim.argsSha256)||!/^[a-f0-9]{32}$/.test(claim.nonce)||!Number.isInteger(claim.expiresAt))throw new Error('INVALID_GRANT');
    for(const k of ['action','deviceId','ownerId','tenantId'])if(typeof claim[k]!=='string'||!ID.test(claim[k]))throw new Error('INVALID_GRANT');
    const value=Buffer.from(JSON.stringify({aud:'rian-tenant-job-v1',...claim})).toString('base64url');
    return value+'.'+createHmac('sha256',this.#secret).update(value).digest('hex');
  }
  verify(proof,now){
    if(typeof proof!=='string'||proof.length>2000)deny();
    const [data,sig,...extra]=proof.split('.');
    if(extra.length||!data||!sig||!HEX.test(sig)||!/^[A-Za-z0-9_-]+$/.test(data))deny();
    const expected=createHmac('sha256',this.#secret).update(data).digest();
    if(!timingSafeEqual(expected,Buffer.from(sig,'hex')))deny();
    let claim;try{claim=JSON.parse(Buffer.from(data,'base64url').toString());}catch{deny();}
    if(!claim||claim.aud!=='rian-tenant-job-v1'||Object.keys(claim).sort().join(',')!=='action,argsSha256,aud,deviceId,expiresAt,nonce,ownerId,tenantId')deny();
    if(!Number.isInteger(claim.expiresAt)||claim.expiresAt<=now||claim.expiresAt>now+300||!/^[a-f0-9]{32}$/.test(claim.nonce||'')||!HEX.test(claim.argsSha256||''))deny();
    return claim;
  }
}
export class TenantJobQueue {
  #directory;#approval;#clock;#jobs=new Map();#queue=new Map();#used=new Map();
  constructor({directory,approval,clock=()=>Date.now()}){
    if(!(directory instanceof TenantDirectory)||!(approval instanceof OwnerJobApproval))throw new Error('INVALID_JOB_QUEUE');
    this.#directory=directory;this.#approval=approval;this.#clock=clock;
  }
  #now(){return Math.floor(this.#clock()/1000);}
  #record(jobId){const j=this.#jobs.get(jobId);if(!j)throw new Error('JOB_NOT_FOUND');return j;}
  enqueue({actor,deviceId,action,args,approvalProof}){
    this.#directory.assertOwner(actor);
    this.#directory.assertDevice(actor.tenantId,deviceId);
    const safe=validateJobAction(action,args);
    const now=this.#now();
    const queueKey=actor.tenantId+'|'+deviceId;
    const q=(this.#queue.get(queueKey)||[]).filter(id=>this.#jobs.get(id)?.state==='PENDING'&&this.#jobs.get(id).deadline>now);
    this.#queue.set(queueKey,q);
    if(q.length>=3)throw new Error('QUEUE_FULL');
    if(PRIV.has(action)){
      const grant=this.#approval.verify(approvalProof,now);
      if(grant.tenantId!==actor.tenantId||grant.ownerId!==actor.id||grant.deviceId!==deviceId||grant.action!==action||grant.argsSha256!==sha(JSON.stringify(safe)))deny();
      if(this.#used.has(grant.nonce))throw new Error('APPROVAL_REPLAY');
      this.#used.set(grant.nonce,grant.expiresAt);
    }
    const job={id:randomUUID(),tenantId:actor.tenantId,ownerId:actor.id,deviceId,action,args:safe,state:'PENDING',createdAt:now,deadline:now+180,leaseUntil:null,result:null};
    this.#jobs.set(job.id,job);q.push(job.id);this.#queue.set(queueKey,q);
    return {jobId:job.id,state:job.state};
  }
  poll(actor,deviceId){
    this.#directory.assertActor(actor);
    this.#directory.assertAgent(actor,actor.tenantId,deviceId);
    const queueKey=actor.tenantId+'|'+deviceId;
    const q=this.#queue.get(queueKey)||[];
    while(q.length){const j=this.#jobs.get(q.shift());if(j?.state==='PENDING'){
      if(j.deadline<=this.#now()){j.state='EXPIRED';continue;}
      j.state='RUNNING';j.leaseUntil=this.#now()+120;
      return {jobId:j.id,action:j.action,args:structuredClone(j.args),leaseUntil:j.leaseUntil};
    }}return {job:null};
  }
  complete(actor,{jobId,result}){
    const j=this.#record(jobId);
    this.#directory.assertAgent(actor,j.tenantId,j.deviceId);
    if(j.state!=='RUNNING'||j.leaseUntil<=this.#now())throw new Error('JOB_NOT_RUNNING');
    if(!result||typeof result!=='object'||Array.isArray(result)||Object.keys(result).sort().join(',')!=='exitCode,output'||!Number.isInteger(result.exitCode)||typeof result.output!=='string'||Buffer.byteLength(result.output)>100000)throw new Error('INVALID_RESULT');
    j.state='DONE';j.result={exitCode:result.exitCode,output:result.output};
    return {jobId:j.id,state:j.state};
  }
  get(actor,jobId){
    this.#directory.assertOwner(actor);
    const j=this.#record(jobId);
    if(j.tenantId!==actor.tenantId)deny();
    return {jobId:j.id,deviceId:j.deviceId,action:j.action,state:j.state,createdAt:j.createdAt,deadline:j.deadline,result:j.result};
  }
  cancel(actor,jobId){
    this.#directory.assertOwner(actor);
    const j=this.#record(jobId);
    if(j.tenantId!==actor.tenantId)deny();
    if(j.state==='DONE')throw new Error('ALREADY_DONE');
    j.state=j.state==='RUNNING'?'CANCEL_REQUESTED':'CANCELLED';return {jobId:j.id,state:j.state};
  }
  reap(){
    const now=this.#now();
    for(const j of this.#jobs.values()){
      if(j.state==='PENDING'&&j.deadline<=now)j.state='EXPIRED';
      if(['RUNNING','CANCEL_REQUESTED'].includes(j.state)&&j.leaseUntil<=now)j.state='UNKNOWN_DO_NOT_RETRY';
    }
    for(const [nonce,exp] of this.#used)if(exp<=now)this.#used.delete(nonce);
  }
}
