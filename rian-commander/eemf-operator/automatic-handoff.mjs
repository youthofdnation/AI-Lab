/** P2 local hook receiver. No hook installation, daemon, remote API, or credential export. */
import {execFileSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {chmodSync,closeSync,existsSync,lstatSync,mkdirSync,openSync,readFileSync,realpathSync,
  renameSync,rmSync,unlinkSync,writeFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {basename,dirname,isAbsolute,join,relative,sep} from 'node:path';
import {buildHandoff,classifyClaudeStop,inspectWorktree,saveLocalHandoff} from './agent-handoff.mjs';
import {executeApprovedHandoff} from './manual-handoff.mjs';

const assert=(v,c)=>{if(!v)throw Error(c);};
const hash=x=>createHash('sha256').update(x).digest('hex');
const inside=(root,p)=>{const r=relative(root,p);return r===''||(r!=='..'&&!r.startsWith('..'+sep)&&!isAbsolute(r));};
const defaultStore=()=>join(homedir(),'.rian-commander','handoffs');
const uuid=/^[a-f0-9-]{36}$/i;
const safeNote=/-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:sk-(?:proj-)?|gh[pousr]_|xox[baprs]-)[A-Za-z0-9_-]{12,}|\bBearer\s+[A-Za-z0-9._-]{12,}|\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*['"]?\S{12,}/i;
const privatePath=/(?:^|[\s\/])(?:\.env|\.ssh|\.claude|\.codex|credentials\.json|auth\.json)(?:$|[\s\/])/i;

function storeAt(dir,worktree){
  assert(isAbsolute(dir),'ABSOLUTE_STORE_REQUIRED');
  assert(!inside(worktree,dir),'STORE_INSIDE_WORKTREE_DENIED');
  if(existsSync(dir))assert(!lstatSync(dir).isSymbolicLink(),'SYMLINK_STORE_DENIED');
  mkdirSync(dir,{recursive:true,mode:0o700});
  const real=realpathSync(dir);
  assert(!inside(worktree,real),'STORE_INSIDE_WORKTREE_DENIED');
  if(process.platform!=='win32')chmodSync(real,0o700);
  return real;
}
function privateDir(parent,name){
  const dir=join(parent,name);
  if(existsSync(dir))assert(!lstatSync(dir).isSymbolicLink(),'SYMLINK_STORE_DENIED');
  mkdirSync(dir,{mode:0o700,recursive:true});
  if(process.platform!=='win32')chmodSync(dir,0o700);
  return dir;
}
function atomic(file,obj){
  const temp=file+'.'+randomUUID()+'.tmp';
  try{
    const fd=openSync(temp,'wx',0o600);
    try{writeFileSync(fd,JSON.stringify(obj,null,2)+'\n');}finally{closeSync(fd);}
    if(process.platform!=='win32')chmodSync(temp,0o600);
    renameSync(temp,file);
  }finally{if(existsSync(temp))rmSync(temp);}
}
function readPrivate(file){
  const st=lstatSync(file,{throwIfNoEntry:false});
  assert(st?.isFile()&&!st.isSymbolicLink()&&st.size<=64_000,'UNSAFE_PRIVATE_RECORD');
  if(process.platform!=='win32')assert((st.mode&0o077)===0,'PRIVATE_RECORD_PERMISSIONS');
  return JSON.parse(readFileSync(file,'utf8'));
}

/** Fixed project-local path and exact schema; unknown fields never grant powers. */
export function readActivationManifest(manifestPath){
  assert(typeof manifestPath==='string'&&isAbsolute(manifestPath),'ABSOLUTE_MANIFEST_REQUIRED');
  const st=lstatSync(manifestPath,{throwIfNoEntry:false});
  assert(st?.isFile()&&!st.isSymbolicLink()&&st.size<=16_000,'UNSAFE_MANIFEST');
  assert(basename(manifestPath)==='activation.json'&&basename(dirname(manifestPath))==='.rian-handoff','PROJECT_MANIFEST_PATH_REQUIRED');
  const path=realpathSync(manifestPath),m=JSON.parse(readFileSync(path,'utf8'));
  assert(m?.schema==='rian-auto-handoff/v1'&&m.enabled===true,'ACTIVATION_DISABLED');
  assert(Object.keys(m).every(k=>['schema','enabled','project','task','permissions','budget'].includes(k)),'UNKNOWN_MANIFEST_FIELD');
  assert(m.project&&Object.keys(m.project).every(k=>['approvedRoot','worktree'].includes(k)),'INVALID_PROJECT_SCOPE');
  assert(isAbsolute(m.project.approvedRoot)&&isAbsolute(m.project.worktree),'INVALID_PROJECT_SCOPE');
  const worktree=realpathSync(m.project.worktree),approvedRoot=realpathSync(m.project.approvedRoot);
  assert(inside(approvedRoot,worktree)&&inside(worktree,path),'MANIFEST_OUTSIDE_PROJECT_SCOPE');
  assert(path===join(worktree,'.rian-handoff','activation.json'),'PROJECT_MANIFEST_PATH_REQUIRED');
  assert(m.task&&Object.keys(m.task).every(k=>['taskId','goal','pendingSteps','testSummary'].includes(k)),'INVALID_TASK_SCOPE');
  assert(typeof m.task.taskId==='string'&&/^[A-Za-z0-9_-]{8,80}$/.test(m.task.taskId),'INVALID_TASK_ID');
  assert(typeof m.task.goal==='string'&&m.task.goal.trim()&&m.task.goal.length<=4000,'INVALID_TASK_SCOPE');
  for(const [v,n,max] of [[m.task.pendingSteps,20,500],[m.task.testSummary,30,500]])
    assert(Array.isArray(v)&&v.length<=n&&v.every(x=>typeof x==='string'&&x.trim()&&x.length<=max),'INVALID_TASK_SCOPE');
  const notes=[m.task.goal,...m.task.pendingSteps,...m.task.testSummary].join('\n');
  assert(!safeNote.test(notes)&&!privatePath.test(notes),'SENSITIVE_HANDOFF_NOTES_DENIED');
  assert(m.permissions&&Object.keys(m.permissions).every(k=>['workspaceWrite','exclusiveWorktree','allowedProviders'].includes(k)),'INVALID_PERMISSIONS');
  assert(typeof m.permissions.workspaceWrite==='boolean'&&m.permissions.exclusiveWorktree===true&&
    JSON.stringify(m.permissions.allowedProviders)==='["claude","codex"]','INVALID_PERMISSIONS');
  assert(m.budget&&Object.keys(m.budget).every(k=>['timeoutMs','checkpointMaxAgeMs'].includes(k)),'INVALID_BUDGET');
  assert(Number.isInteger(m.budget.timeoutMs)&&m.budget.timeoutMs>=1000&&m.budget.timeoutMs<=120_000,'INVALID_BUDGET');
  assert(Number.isInteger(m.budget.checkpointMaxAgeMs)&&m.budget.checkpointMaxAgeMs>=1000&&m.budget.checkpointMaxAgeMs<=1_800_000,'INVALID_BUDGET');
  return {manifest:m,path,worktree,approvedRoot,digest:hash(readFileSync(path))};
}

/** Owner approval is a private digest seal tied to the exact worktree and manifest bytes. */
export function authorizeActivation({manifestPath,storeDir=defaultStore(),ownerApproved=false}){
  assert(ownerApproved===true,'OWNER_APPROVAL_REQUIRED');
  const a=readActivationManifest(manifestPath),store=storeAt(storeDir,a.worktree);
  const sealPath=join(privateDir(store,'activation-seals'),hash(a.worktree)+'.json');
  const seal={schema:'rian-activation-seal/v1',worktree:a.worktree,manifestPath:a.path,digest:a.digest,
    approvedAt:new Date().toISOString(),workspaceWrite:a.manifest.permissions.workspaceWrite,
    timeoutMs:a.manifest.budget.timeoutMs};
  atomic(sealPath,seal);
  return {sealPath,worktree:a.worktree,digest:a.digest};
}
function approved(manifestPath,storeDir){
  const a=readActivationManifest(manifestPath),store=storeAt(storeDir,a.worktree);
  const seal=readPrivate(join(store,'activation-seals',hash(a.worktree)+'.json'));
  assert(seal.schema==='rian-activation-seal/v1'&&seal.worktree===a.worktree&&seal.manifestPath===a.path&&
    seal.digest===a.digest&&seal.workspaceWrite===a.manifest.permissions.workspaceWrite&&
    seal.timeoutMs===a.manifest.budget.timeoutMs,'ACTIVATION_SEAL_MISMATCH');
  return {...a,store};
}

/** Fingerprint dirty content in memory. No diffs or file contents are stored. */
function fingerprint(repo){
  const wd=repo.worktree;
  const diff=execFileSync('git',['-C',wd,'diff','--binary','HEAD','--'],{maxBuffer:8*1024*1024,timeout:12000});
  const files=execFileSync('git',['-C',wd,'ls-files','--others','--exclude-standard','-z'],{maxBuffer:1024*1024,timeout:12000})
    .toString('utf8').split('\0').filter(Boolean).sort();
  assert(files.length<=200,'UNTRACKED_FILE_LIMIT');
  const h=createHash('sha256').update(diff);
  for(const file of files){
    const path=join(wd,file),st=lstatSync(path);
    assert(st.isFile()&&!st.isSymbolicLink()&&st.size<=1024*1024,'UNSAFE_UNTRACKED_FILE');
    h.update(file).update('\0').update(readFileSync(path));
  }
  return h.digest('hex');
}
const sessionKey=(worktree,session)=>hash(worktree+'\0'+session);
const validSession=x=>typeof x==='string'&&/^[A-Za-z0-9_-]{3,128}$/.test(x);

export const codexReceiver={
  name:'codex',
  async dispatch({checkpointPath,approvedRoot,store,timeoutMs,codexCommand,codexPrefixArgs,onProgress,beforeDispatch}){
    return executeApprovedHandoff({checkpointPath,approvedRoot,storeDir:store,ownerApproved:true,
      timeoutMs,codexCommand,codexPrefixArgs,onProgress,beforeDispatch,strictAuto:true});
  }
};

/** Called with official hook stdin. Test seams are only available to direct module callers. */
export async function handleClaudeHook({event,manifestPath,storeDir=defaultStore(),receiver=codexReceiver,
  codexCommand='codex',codexPrefixArgs=[]}){
  assert(event&&typeof event==='object'&&validSession(event.session_id),'INVALID_HOOK_EVENT');
  const a=approved(manifestPath,storeDir);
  assert(typeof event.cwd==='string'&&realpathSync(event.cwd)===a.worktree,'HOOK_WORKTREE_MISMATCH');
  const key=sessionKey(a.worktree,event.session_id),cpDir=privateDir(a.store,'incremental');
  const cpPath=join(cpDir,key+'.json');
  const kind=event.hook_event_name;
  if(['SessionStart','UserPromptSubmit','PostToolUse','PostToolUseFailure'].includes(kind)){
    const repo=inspectWorktree({approvedRoot:a.approvedRoot,worktree:a.worktree});
    assert(repo.omittedSensitivePaths===0,'SENSITIVE_WORKTREE_PATHS_DENIED');
    const previous=existsSync(cpPath)?readPrivate(cpPath):null;
    const record={schema:'rian-incremental/v1',sessionId:event.session_id,manifestDigest:a.digest,
      repository:repo,contentFingerprint:fingerprint(repo),sequence:(previous?.sequence||0)+1,
      savedAt:new Date().toISOString(),event:kind};
    atomic(cpPath,record);
    return {state:'CHECKPOINTED',sequence:record.sequence};
  }
  if(kind!=='StopFailure'||classifyClaudeStop(event)!=='CLAUDE_RATE_LIMIT')
    return {state:'IGNORED',reason:classifyClaudeStop(event)};
  const cp=readPrivate(cpPath);
  assert(cp.schema==='rian-incremental/v1'&&cp.sessionId===event.session_id&&cp.manifestDigest===a.digest,'CHECKPOINT_SCOPE_MISMATCH');
  const dispatchMarker=join(privateDir(a.store,'automatic-dispatch'),key+'.json');
  assert(!existsSync(dispatchMarker),'AUTOMATIC_DISPATCH_ALREADY_ATTEMPTED');
  const taskMarker=join(privateDir(a.store,'task-dispatch'),hash(a.worktree+'\0'+a.manifest.task.taskId+'\0'+a.digest)+'.json');
  assert(!existsSync(taskMarker),'PROJECT_TASK_ALREADY_ATTEMPTED');
  assert(Date.now()-Date.parse(cp.savedAt)<=a.manifest.budget.checkpointMaxAgeMs,'CHECKPOINT_EXPIRED');
  const repo=inspectWorktree({approvedRoot:a.approvedRoot,worktree:a.worktree});
  assert(repo.omittedSensitivePaths===0,'SENSITIVE_WORKTREE_PATHS_DENIED');
  assert(repo.head===cp.repository.head&&repo.branch===cp.repository.branch&&
    JSON.stringify(repo.changed)===JSON.stringify(cp.repository.changed)&&fingerprint(repo)===cp.contentFingerprint,
    'WORKTREE_CHANGED_AFTER_CHECKPOINT');
  // Atomic exclusive create is the durable no-duplicate gate, including crashes before receipt creation.
  // The task marker also blocks a later Claude session from replaying the same approved task.
  let taskFd;
  try{taskFd=openSync(taskMarker,'wx',0o600);}catch(e){if(e?.code==='EEXIST')throw Error('PROJECT_TASK_ALREADY_ATTEMPTED');throw e;}
  try{writeFileSync(taskFd,JSON.stringify({taskId:a.manifest.task.taskId,sessionId:event.session_id,state:'CLAIMED',at:new Date().toISOString()}));}
  finally{closeSync(taskFd);}
  let fd;
  try{fd=openSync(dispatchMarker,'wx',0o600);}catch(e){if(e?.code==='EEXIST')throw Error('AUTOMATIC_DISPATCH_ALREADY_ATTEMPTED');throw e;}
  const dispatchId=randomUUID();
  try{writeFileSync(fd,JSON.stringify({dispatchId,sessionId:event.session_id,state:'CLAIMED',at:new Date().toISOString()}));}
  finally{closeSync(fd);}
  const update=(state,extra={})=>atomic(dispatchMarker,{dispatchId,sessionId:event.session_id,state,at:new Date().toISOString(),...extra});
  try{
    const handoff=buildHandoff({taskId:a.manifest.task.taskId,goal:a.manifest.task.goal,repo,
      pendingSteps:a.manifest.task.pendingSteps,testSummary:a.manifest.task.testSummary,event,
      ownerScope:{allowedProviders:a.manifest.permissions.allowedProviders,workspaceWrite:a.manifest.permissions.workspaceWrite},activeJobs:[]});
    const checkpointPath=saveLocalHandoff(handoff,{directory:a.store});
    update('READY',{handoffId:handoff.handoffId});
    const result=await receiver.dispatch({checkpointPath,approvedRoot:a.approvedRoot,store:a.store,
      timeoutMs:a.manifest.budget.timeoutMs,codexCommand,codexPrefixArgs,
      beforeDispatch:()=>{
        assert(approved(manifestPath,storeDir).digest===a.digest,'ACTIVATION_CHANGED_BEFORE_DISPATCH');
        const latest=inspectWorktree({approvedRoot:a.approvedRoot,worktree:a.worktree});
        assert(latest.head===repo.head&&latest.branch===repo.branch&&
          JSON.stringify(latest.changed)===JSON.stringify(repo.changed)&&fingerprint(latest)===cp.contentFingerprint,
          'WORKTREE_CHANGED_BEFORE_DISPATCH');
      },
      onProgress:p=>update('RUNNING',{handoffId:handoff.handoffId,events:p.events,threadId:p.threadId,failureKind:p.failureKind})});
    update(result.state,{handoffId:handoff.handoffId,events:result.events,threadId:result.threadId,
      failureKind:result.failureKind||null,lockRetained:result.lockRetained});
    return {state:result.state,handoffId:handoff.handoffId,threadId:result.threadId,lockRetained:result.lockRetained};
  }catch(e){
    update('BLOCKED_REVIEW',{reason:String(e?.message||'UNKNOWN').slice(0,120)});
    throw e;
  }
}

/** Audited unlock only. It never replays the same session's dispatch marker. */
export function reconcileAutomaticLease({manifestPath,storeDir=defaultStore(),handoffId,ownerVerifiedNoWriter=false,reason=''}){
  assert(ownerVerifiedNoWriter===true,'OWNER_VERIFICATION_REQUIRED');
  assert(uuid.test(handoffId)&&typeof reason==='string'&&reason.trim().length>=12&&reason.length<=500,'INVALID_RECOVERY_REQUEST');
  assert(!safeNote.test(reason)&&!privatePath.test(reason),'SENSITIVE_RECOVERY_REASON_DENIED');
  const a=approved(manifestPath,storeDir),receiptPath=join(a.store,'receipts',handoffId+'.json');
  const receipt=existsSync(receiptPath)?readPrivate(receiptPath):null;
  assert(!receipt||['UNKNOWN_DO_NOT_RETRY','DISPATCHING','RUNNING'].includes(receipt.state),'RECOVERY_STATE_DENIED');
  const lockPath=join(a.store,'leases',hash(a.worktree)+'.lock'),lock=readPrivate(lockPath);
  assert(lock.handoffId===handoffId&&lock.worktree===a.worktree&&uuid.test(lock.attemptId)&&
    (!receipt||lock.attemptId===receipt.attemptId),'RECOVERY_LEASE_MISMATCH');
  if(Number.isInteger(lock.childPid)){
    try{process.kill(lock.childPid,0);throw Error('CHILD_PROCESS_STILL_ALIVE');}
    catch(e){if(e.code!=='ESRCH')throw e;}
  }
  const auditPath=join(privateDir(a.store,'recovery-audit'),randomUUID()+'.json');
  atomic(auditPath,{schema:'rian-recovery/v1',handoffId,attemptId:lock.attemptId,worktree:a.worktree,
    reason:reason.trim(),reconciledAt:new Date().toISOString(),ownerVerifiedNoWriter:true});
  privateDir(a.store,'receipts');
  atomic(receiptPath,{...receipt,handoffId,attemptId:lock.attemptId,provider:'codex',worktree:a.worktree,
    state:'RECONCILED_NO_RETRY',recoveryAudit:auditPath});
  unlinkSync(lockPath);
  return {state:'RECONCILED_NO_RETRY',auditPath};
}
