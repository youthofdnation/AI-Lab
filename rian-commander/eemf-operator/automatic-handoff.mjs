/** P2 local hook receiver. No hook installation, daemon, remote API, or credential export. */
import {execFileSync,spawn,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createHash,randomUUID} from 'node:crypto';
import {chmodSync,closeSync,existsSync,lstatSync,mkdirSync,openSync,readFileSync,realpathSync,
  renameSync,rmSync,unlinkSync,writeFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {basename,dirname,isAbsolute,join,relative,sep} from 'node:path';
import {buildHandoff,classifyClaudeStop,inspectWorktree,saveLocalHandoff} from './agent-handoff.mjs';
import {executeApprovedHandoff} from './manual-handoff.mjs';
import {capturePrompt,consumeGrantRun,grantRunsUsed,planGrant,readGrant,revokeGrant,saveGrant,taskFromPrompt} from './handoff-grant.mjs';

/**
 * One owner approval per device + worktree (Issue #9). `confirm(plan)` must obtain the owner's own
 * decision (native dialog click or terminal) and return the method; it throws when declined.
 */
export async function createProjectGrant({worktree,storeDir=defaultStore(),runs,days,runMinutes,workspaceWrite=true,confirm}){
  const plan=planGrant({worktree,runs,days,runMinutes,workspaceWrite});
  const store=storeAt(storeDir,plan.worktree);
  assert(typeof confirm==='function','OWNER_APPROVAL_REQUIRED');
  const approvedVia=await confirm(plan);
  return saveGrant({grant:plan,store,approvedVia});
}
export function revokeProjectGrant({worktree,storeDir=defaultStore(),reason}){
  const real=realpathSync(worktree);
  return revokeGrant({worktree:real,store:storeAt(storeDir,real),reason});
}

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
  // Up to 30 minutes: the Codex run is detached from the Claude hook, so it is not bound by the hook timeout.
  assert(Number.isInteger(m.budget.timeoutMs)&&m.budget.timeoutMs>=1000&&m.budget.timeoutMs<=1_800_000,'INVALID_BUDGET');
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
  const sealPath=join(store,'activation-seals',hash(a.worktree)+'.json');
  assert(existsSync(sealPath),'ACTIVATION_NOT_APPROVED');
  const seal=readPrivate(sealPath);
  assert(seal.schema==='rian-activation-seal/v1'&&seal.worktree===a.worktree&&seal.manifestPath===a.path&&
    seal.digest===a.digest&&seal.workspaceWrite===a.manifest.permissions.workspaceWrite&&
    seal.timeoutMs===a.manifest.budget.timeoutMs,'ACTIVATION_SEAL_MISMATCH');
  return {...a,store};
}
/** P2 manifest seal or P2.2 project grant (Issue #9), normalized to one authority shape. */
function authorityFor({manifestPath,grantWorktree},storeDir){
  if(manifestPath)return {...approved(manifestPath,storeDir),mode:'manifest'};
  assert(typeof grantWorktree==='string'&&isAbsolute(grantWorktree),'GRANT_NOT_FOUND');
  let worktree;try{worktree=realpathSync(grantWorktree);}catch{throw Error('GRANT_NOT_FOUND');}
  const store=storeAt(storeDir,worktree),{grant,digest}=readGrant({worktree,store});
  return {mode:'grant',grant,digest,worktree,approvedRoot:grant.approvedRoot,store,path:null,
    manifest:{task:null,permissions:{workspaceWrite:grant.permissions.workspaceWrite,exclusiveWorktree:true,allowedProviders:['claude','codex']},
      budget:{timeoutMs:grant.runTimeoutMs,checkpointMaxAgeMs:grant.checkpointMaxAgeMs}}};
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

/** Every blocked hook gets a category the owner can act on. */
export function categorizeHandoffError(code){
  const c=String(code||'');
  if(/^(ACTIVATION_|OWNER_APPROVAL|GRANT_|OWNER_DIALOG)/.test(c))return 'APPROVAL';
  if(/^(CHECKPOINT_|WORKTREE_CHANGED|GIT_WORKTREE_CHANGED|SENSITIVE_WORKTREE|UNTRACKED_FILE_LIMIT|UNSAFE_UNTRACKED|CHANGED_FILE_LIMIT)/.test(c))return 'CHECKPOINT';
  if(/^(CODEX_|PROVIDER_|NETWORK_|USAGE_LIMIT|TIMEOUT|UNKNOWN_DO_NOT_RETRY|AUTOMATIC_DISPATCH|PROJECT_TASK|HANDOFF_ALREADY|WORKTREE_ALREADY_LEASED|INVALID_RUNTIME)/.test(c))return 'EXECUTION';
  return 'CONFIGURATION';
}
const HOOK_EVENTS=['SessionStart','UserPromptSubmit','PostToolUse','PostToolUseFailure','StopFailure'];
const DUPLICATE=/^(AUTOMATIC_DISPATCH_ALREADY_ATTEMPTED|PROJECT_TASK_ALREADY_ATTEMPTED|DISPATCH_NOT_PENDING|DISPATCH_RUNNER_ALREADY_STARTED)$/;
function manifestWorktree(manifestPath){
  try{return readActivationManifest(manifestPath).worktree;}catch{}
  try{return realpathSync(dirname(dirname(manifestPath)));}catch{return null;}
}
/** Claude ignores StopFailure output, so the last outcome is kept in the private store for `status`. */
function recordHookStatus({manifestPath,grantWorktree,storeDir,event,result,error}){
  try{
    let worktree=null;
    if(manifestPath)worktree=manifestWorktree(manifestPath);
    else if(typeof grantWorktree==='string'&&isAbsolute(grantWorktree)){try{worktree=realpathSync(grantWorktree);}catch{}}
    if(!worktree)return;
    const store=storeAt(storeDir,worktree),file=join(privateDir(store,'hook-status'),hash(worktree)+'.json');
    let previous={};try{if(existsSync(file))previous=readPrivate(file);}catch{}
    const kind=HOOK_EVENTS.includes(event?.hook_event_name)?event.hook_event_name:'UNKNOWN_EVENT';
    const entry={at:new Date().toISOString(),event:kind,sessionId:validSession(event?.session_id)?event.session_id:null,
      state:error?'BLOCKED':result?.state,error:error?String(error.message||'HANDOFF_ERROR').slice(0,80):null,
      category:error?categorizeHandoffError(error.message):null,
      ...(result?.sequence?{sequence:result.sequence}:{}),...(result?.handoffId?{handoffId:result.handoffId,threadId:result.threadId??null,lockRetained:!!result.lockRetained}:{}),
      ...(result?.runnerPid?{runnerPid:result.runnerPid}:{}),
      ...(result?.reason?{reason:result.reason}:{})};
    const record={schema:'rian-hook-status/v1',worktree,lastEvent:entry,
      lastCheckpoint:!error&&result?.state==='CHECKPOINTED'?entry:previous.lastCheckpoint||null,
      lastTrigger:kind==='StopFailure'?entry:previous.lastTrigger||null,
      // Neither an ignored StopFailure (server_error, billing...) nor a rejected duplicate may hide
      // the last real dispatch outcome; both stay visible in lastTrigger and history.
      lastDispatch:kind==='StopFailure'&&entry.state!=='IGNORED'&&!DUPLICATE.test(entry.error||'')?entry:previous.lastDispatch||null,
      history:[...(Array.isArray(previous.history)?previous.history:[]).slice(-19),entry]};
    atomic(file,record);
  }catch{/* status is best effort and never changes the hook outcome */}
}

/** Called with official hook stdin. Test seams are only available to direct module callers. */
export async function handleClaudeHook(options){
  const where={...options,storeDir:options.storeDir??defaultStore(),grantWorktree:options.grant?options.event?.cwd:undefined};
  try{
    const result=await handleClaudeHookChecked(options);
    recordHookStatus({...where,result});
    return result;
  }catch(error){
    recordHookStatus({...where,error});
    throw error;
  }
}

/** Read-only readiness report: manifest, owner approval, checkpoints, last trigger, lease, Codex login. */
export function automaticHandoffStatus({manifestPath,storeDir=defaultStore(),codexCommand='codex',codexPrefixArgs=[],probeCodex=true,now=Date.now()}){
  const out={manifest:null,approval:null,lastCheckpoint:null,lastTrigger:null,lease:null,taskAttempted:false,codex:null,blockers:[],warnings:[]};
  let a;
  try{a=readActivationManifest(manifestPath);}
  catch(e){out.manifest={state:'INVALID',error:e.message,category:'CONFIGURATION'};out.blockers.push(e.message);out.ready=false;return out;}
  const m=a.manifest;
  out.manifest={state:'VALID',worktree:a.worktree,approvedRoot:a.approvedRoot,taskId:m.task.taskId,goal:m.task.goal,
    workspaceWrite:m.permissions.workspaceWrite,timeoutMs:m.budget.timeoutMs,checkpointMaxAgeMs:m.budget.checkpointMaxAgeMs,digest:a.digest.slice(0,12)};
  const store=isAbsolute(storeDir)&&existsSync(storeDir)?realpathSync(storeDir):null;
  const key=hash(a.worktree);
  try{
    const seal=approved(manifestPath,storeDir);
    out.approval={state:'APPROVED',approvedAt:readPrivate(join(seal.store,'activation-seals',key+'.json')).approvedAt};
  }catch(e){
    out.approval={state:e.message==='ACTIVATION_SEAL_MISMATCH'?'CHANGED_REAPPROVAL_REQUIRED':e.message==='ACTIVATION_NOT_APPROVED'?'NOT_APPROVED':'ERROR',error:e.message};
    out.blockers.push(e.message);
  }
  if(store){
    const statusFile=join(store,'hook-status',key+'.json');
    if(existsSync(statusFile)){
      try{
        const s=readPrivate(statusFile);
        if(s.lastCheckpoint){const age=now-Date.parse(s.lastCheckpoint.at);out.lastCheckpoint={...s.lastCheckpoint,ageMs:age,fresh:age<=m.budget.checkpointMaxAgeMs};}
        out.lastTrigger=s.lastTrigger||null;out.lastDispatch=s.lastDispatch||null;out.lastEvent=s.lastEvent||null;
        if(s.lastTrigger?.reason==='OWNER_ATTENTION_REQUIRED')out.warnings.push('OWNER_ATTENTION_REQUIRED: the last Claude stop was an auth/billing/account error, not a rate limit');
        if(s.lastDispatch?.sessionId){
          // The dispatch marker is authoritative (the hook and the detached runner both write status).
          const markerPath=join(store,'automatic-dispatch',sessionKey(a.worktree,s.lastDispatch.sessionId)+'.json');
          let marker=null;try{if(existsSync(markerPath))marker=readPrivate(markerPath);}catch{}
          if(marker)out.lastDispatch={...out.lastDispatch,markerState:marker.state,threadId:marker.threadId??out.lastDispatch.threadId??null};
          if(marker?.state==='DETACHED'||marker?.state==='RUNNING'){
            const pid=marker.runnerPid??s.lastDispatch.runnerPid;let alive=false;
            if(Number.isInteger(pid)){try{process.kill(pid,0);alive=true;}catch{}}
            out.lastDispatch.runnerAlive=alive;
            if(!alive)out.warnings.push('DETACHED_RUNNER_EXITED_WITHOUT_RESULT: inspect receipts/leases, then use recover');
          }
        }
      }catch(e){out.warnings.push('HOOK_STATUS_UNREADABLE');}
    }
    const lockPath=join(store,'leases',key+'.lock');
    if(existsSync(lockPath)){
      try{const lock=readPrivate(lockPath);let alive=false;
        if(Number.isInteger(lock.childPid)){try{process.kill(lock.childPid,0);alive=true;}catch{}}
        out.lease={state:'HELD',handoffId:lock.handoffId,childAlive:alive};}catch{out.lease={state:'HELD_UNREADABLE'};}
      out.blockers.push('WORKTREE_ALREADY_LEASED');
    }
    if(existsSync(join(store,'task-dispatch',hash(a.worktree+'\0'+m.task.taskId+'\0'+a.digest)+'.json'))){
      out.taskAttempted=true;out.blockers.push('PROJECT_TASK_ALREADY_ATTEMPTED');
    }
  }
  if(!out.lastCheckpoint)out.warnings.push('NO_CHECKPOINT_YET: hooks have not run for this worktree (check hook install, folder trust, exact worktree root)');
  else if(!out.lastCheckpoint.fresh)out.warnings.push('CHECKPOINT_STALE: a rate limit now would be refused until the next hook event');
  if(probeCodex){
    const run=args=>spawnSync(codexCommand,[...codexPrefixArgs,...args],{timeout:10000,encoding:'utf8',maxBuffer:8192,windowsHide:true});
    const v=run(['--version']),l=v.status===0?run(['login','status']):null;
    out.codex={available:v.status===0,version:v.status===0?String(v.stdout).trim().slice(0,60):null,loggedIn:l?.status===0};
    if(!out.codex.available)out.blockers.push('CODEX_EXECUTABLE_UNAVAILABLE');
    else if(!out.codex.loggedIn)out.blockers.push('CODEX_NOT_AUTHENTICATED');
  }
  out.blockers=out.blockers.map(code=>({code,category:categorizeHandoffError(code)}));
  out.ready=out.blockers.length===0;
  return out;
}

async function handleClaudeHookChecked({event,manifestPath,grant=false,storeDir=defaultStore(),receiver=codexReceiver,
  codexCommand='codex',codexPrefixArgs=[],detach=false,spawnRunner=spawnDetachedRunner}){
  assert(event&&typeof event==='object'&&validSession(event.session_id),'INVALID_HOOK_EVENT');
  // Grant mode: the project grant is looked up from the session's own worktree (event.cwd).
  const desc=grant?{grantWorktree:event.cwd}:{manifestPath};
  const a=authorityFor(desc,storeDir);
  assert(typeof event.cwd==='string'&&realpathSync(event.cwd)===a.worktree,'HOOK_WORKTREE_MISMATCH');
  const key=sessionKey(a.worktree,event.session_id),cpDir=privateDir(a.store,'incremental');
  const cpPath=join(cpDir,key+'.json');
  const kind=event.hook_event_name;
  if(['SessionStart','UserPromptSubmit','PostToolUse','PostToolUseFailure'].includes(kind)){
    const repo=inspectWorktree({approvedRoot:a.approvedRoot,worktree:a.worktree});
    assert(repo.omittedSensitivePaths===0,'SENSITIVE_WORKTREE_PATHS_DENIED');
    const previous=existsSync(cpPath)?readPrivate(cpPath):null;
    // Grant mode only: the owner's latest prompt is the task Codex would continue (kept local, 0600).
    const captured=a.mode==='grant'&&kind==='UserPromptSubmit'?capturePrompt(event.prompt):null;
    const record={schema:'rian-incremental/v1',sessionId:event.session_id,manifestDigest:a.digest,
      repository:repo,contentFingerprint:fingerprint(repo),sequence:(previous?.sequence||0)+1,
      savedAt:new Date().toISOString(),event:kind,
      ...(a.mode==='grant'?{lastPrompt:captured?captured.prompt:previous?.lastPrompt??null,
        promptRejected:captured?captured.rejected:previous?.promptRejected??null}:{})};
    atomic(cpPath,record);
    return {state:'CHECKPOINTED',sequence:record.sequence,...(a.mode==='grant'?{taskCaptured:!!record.lastPrompt}:{})};
  }
  if(kind!=='StopFailure'||classifyClaudeStop(event)!=='CLAUDE_RATE_LIMIT')
    return {state:'IGNORED',reason:classifyClaudeStop(event)};
  // No checkpoint from this Claude session: hooks did not run (not installed, untrusted folder,
  // other worktree) or a different session hit the limit. Never dispatch without one.
  assert(existsSync(cpPath),'CHECKPOINT_MISSING');
  const cp=readPrivate(cpPath);
  assert(cp.schema==='rian-incremental/v1'&&cp.sessionId===event.session_id&&cp.manifestDigest===a.digest,'CHECKPOINT_SCOPE_MISMATCH');
  if(a.mode==='grant'){
    assert(!cp.promptRejected,cp.promptRejected||'CHECKPOINT_PROMPT_SENSITIVE');
    a.manifest.task=taskFromPrompt(cp.lastPrompt);   // CHECKPOINT_NO_TASK_PROMPT when none was captured
  }
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
  let grantRun=null;
  if(a.mode==='grant'){
    // Counted only after the single-shot markers succeed, so duplicates never consume a run.
    try{grantRun=consumeGrantRun({grant:a.grant,store:a.store,handoffId:dispatchId});}
    catch(e){update('BLOCKED_REVIEW',{reason:String(e?.message||'UNKNOWN').slice(0,120)});throw e;}
  }
  let handoff,checkpointPath;
  try{
    handoff=buildHandoff({taskId:a.manifest.task.taskId,goal:a.manifest.task.goal,repo,
      pendingSteps:a.manifest.task.pendingSteps,testSummary:a.manifest.task.testSummary,event,
      ownerScope:{allowedProviders:a.manifest.permissions.allowedProviders,workspaceWrite:a.manifest.permissions.workspaceWrite},activeJobs:[]});
    checkpointPath=saveLocalHandoff(handoff,{directory:a.store});
  }catch(e){update('BLOCKED_REVIEW',{reason:String(e?.message||'UNKNOWN').slice(0,120)});throw e;}
  // Reference state the runner re-verifies right before Codex starts (metadata + digest only).
  const ref={head:repo.head,branch:repo.branch,changed:repo.changed,fingerprint:cp.contentFingerprint};
  if(detach){
    // The hook only validates and claims; a detached runner does the long Codex run, so Claude's
    // hook timeout no longer caps the work. The claim markers above still make it single-shot.
    update('DETACHED',{handoffId:handoff.handoffId,checkpointPath,ref});
    let runnerPid;
    const target=a.mode==='grant'?['--worktree',a.worktree]:['--manifest',manifestPath];
    try{runnerPid=spawnRunner(['dispatch-run',...target,'--store',a.store,'--handoff-id',handoff.handoffId,'--session',event.session_id]);}
    catch(e){update('BLOCKED_REVIEW',{handoffId:handoff.handoffId,reason:'RUNNER_SPAWN_FAILED'});throw Error('RUNNER_SPAWN_FAILED');}
    update('DETACHED',{handoffId:handoff.handoffId,checkpointPath,ref,runnerPid});
    return {state:'DISPATCHED_DETACHED',handoffId:handoff.handoffId,runnerPid,...(grantRun?{grantRun}:{})};
  }
  update('READY',{handoffId:handoff.handoffId});
  const result=await runDispatch({a,desc,storeDir,sessionId:event.session_id,dispatchId,dispatchMarker,checkpointPath,
    handoffId:handoff.handoffId,ref,receiver,codexCommand,codexPrefixArgs});
  return grantRun?{...result,grantRun}:result;
}

const RUNNER_CLI=fileURLToPath(new URL('./automatic-handoff-cli.mjs',import.meta.url));
function spawnDetachedRunner(args){
  const child=spawn(process.execPath,[RUNNER_CLI,...args],{detached:true,stdio:'ignore',windowsHide:true});
  child.unref();
  assert(Number.isInteger(child.pid),'RUNNER_SPAWN_FAILED');
  return child.pid;
}

async function runDispatch({a,desc,storeDir,sessionId,dispatchId,dispatchMarker,checkpointPath,handoffId,ref,receiver,codexCommand,codexPrefixArgs}){
  const update=(state,extra={})=>atomic(dispatchMarker,{dispatchId,sessionId,state,at:new Date().toISOString(),handoffId,...extra});
  try{
    const result=await receiver.dispatch({checkpointPath,approvedRoot:a.approvedRoot,store:a.store,
      timeoutMs:a.manifest.budget.timeoutMs,codexCommand,codexPrefixArgs,
      beforeDispatch:()=>{
        // Re-reads the seal or grant: a revoked/expired grant stops the run before Codex starts.
        assert(authorityFor(desc,storeDir).digest===a.digest,'ACTIVATION_CHANGED_BEFORE_DISPATCH');
        const latest=inspectWorktree({approvedRoot:a.approvedRoot,worktree:a.worktree});
        assert(latest.head===ref.head&&latest.branch===ref.branch&&
          JSON.stringify(latest.changed)===JSON.stringify(ref.changed)&&fingerprint(latest)===ref.fingerprint,
          'WORKTREE_CHANGED_BEFORE_DISPATCH');
      },
      onProgress:p=>update('RUNNING',{events:p.events,threadId:p.threadId,failureKind:p.failureKind})});
    update(result.state,{events:result.events,threadId:result.threadId,failureKind:result.failureKind||null,lockRetained:result.lockRetained});
    return {state:result.state,handoffId,threadId:result.threadId,lockRetained:result.lockRetained};
  }catch(e){
    update('BLOCKED_REVIEW',{reason:String(e?.message||'UNKNOWN').slice(0,120)});
    throw e;
  }
}

/** Detached runner entry (spawned by the StopFailure hook). Runs a DETACHED claim exactly once. */
export async function runDetachedDispatch({manifestPath,grantWorktree,storeDir=defaultStore(),sessionId,handoffId,receiver=codexReceiver,codexCommand='codex',codexPrefixArgs=[]}){
  const event={hook_event_name:'StopFailure',session_id:sessionId};
  const desc=manifestPath?{manifestPath}:{grantWorktree};
  try{
    assert(validSession(sessionId)&&typeof handoffId==='string'&&uuid.test(handoffId),'INVALID_DISPATCH_REQUEST');
    const a=authorityFor(desc,storeDir);
    const dispatchMarker=join(a.store,'automatic-dispatch',sessionKey(a.worktree,sessionId)+'.json');
    assert(existsSync(dispatchMarker),'DISPATCH_NOT_PENDING');
    const marker=readPrivate(dispatchMarker);
    assert(marker.state==='DETACHED'&&marker.handoffId===handoffId&&marker.sessionId===sessionId&&marker.ref&&marker.checkpointPath,'DISPATCH_NOT_PENDING');
    let fd;
    try{fd=openSync(join(privateDir(a.store,'runner-claims'),handoffId+'.json'),'wx',0o600);}
    catch(e){if(e?.code==='EEXIST')throw Error('DISPATCH_RUNNER_ALREADY_STARTED');throw e;}
    try{writeFileSync(fd,JSON.stringify({pid:process.pid,at:new Date().toISOString()}));}finally{closeSync(fd);}
    const result=await runDispatch({a,desc,storeDir,sessionId,dispatchId:marker.dispatchId,dispatchMarker,
      checkpointPath:marker.checkpointPath,handoffId,ref:marker.ref,receiver,codexCommand,codexPrefixArgs});
    recordHookStatus({...desc,storeDir,event,result});
    return result;
  }catch(error){
    recordHookStatus({...desc,storeDir,event,error});
    throw error;
  }
}

/** Are the five grant hooks present in the worktree's project-local (or project) Claude Code settings? */
const GRANT_HOOK_EVENTS=['SessionStart','UserPromptSubmit','PostToolUse','PostToolUseFailure','StopFailure'];
export function grantHooksInstalled(worktree){
  const found=new Set(),files=[];
  for(const name of ['settings.local.json','settings.json']){
    let cfg;try{cfg=JSON.parse(readFileSync(join(worktree,'.claude',name),'utf8'));}catch{continue;}
    files.push('.claude/'+name);
    for(const ev of GRANT_HOOK_EVENTS)for(const group of Array.isArray(cfg?.hooks?.[ev])?cfg.hooks[ev]:[])
      for(const h of Array.isArray(group?.hooks)?group.hooks:[])
        if(h?.type==='command'&&Array.isArray(h.args)&&h.args.includes('hook-grant')&&
          (ev!=='StopFailure'||!group.matcher||/(^|\|)rate_limit(\||$)/.test(group.matcher)))found.add(ev);
  }
  const missing=GRANT_HOOK_EVENTS.filter(e=>!found.has(e));
  return {installed:missing.length===0,missing,files};
}

/** Read-only status of a project grant: scope, expiry, runs left, checkpoints, last handoff, Codex login. */
export function grantHandoffStatus({worktree,storeDir=defaultStore(),codexCommand='codex',codexPrefixArgs=[],probeCodex=true,now=Date.now()}){
  const out={grant:null,lastCheckpoint:null,lastTrigger:null,lease:null,codex:null,blockers:[],warnings:[]};
  let real;try{real=realpathSync(worktree);}catch{out.blockers.push('GRANT_NOT_FOUND');}
  const store=real&&isAbsolute(storeDir)&&existsSync(storeDir)?realpathSync(storeDir):null;
  let maxAge=900_000;
  if(real&&store){
    try{
      const {grant}=readGrant({worktree:real,store,now});
      const used=grantRunsUsed({grant,store});
      out.grant={state:'ACTIVE',grantId:grant.grantId,device:grant.device,worktree:grant.worktree,approvedVia:grant.approvedVia,approvedAt:grant.approvedAt,
        expiresAt:grant.expiresAt,workspaceWrite:grant.permissions.workspaceWrite,runTimeoutMinutes:Math.round(grant.runTimeoutMs/60000),
        runsUsed:used,runsLeft:Math.max(0,grant.maxRuns-used)};
      maxAge=grant.checkpointMaxAgeMs;
      if(used>=grant.maxRuns)out.blockers.push('GRANT_RUNS_EXHAUSTED');
    }catch(e){out.grant={state:e.message.replace(/^GRANT_/,''),error:e.message};out.blockers.push(e.message);}
  }else if(real)out.blockers.push('GRANT_NOT_FOUND');
  if(real){
    out.hooks=grantHooksInstalled(real);
    if(!out.hooks.installed)out.warnings.push('HOOKS_NOT_INSTALLED: missing '+out.hooks.missing.join(', ')+' in the project-local Claude Code settings');
  }
  if(real&&store){
    const key=hash(real),statusFile=join(store,'hook-status',key+'.json');
    if(existsSync(statusFile)){
      try{
        const s=readPrivate(statusFile);
        if(s.lastCheckpoint){const age=now-Date.parse(s.lastCheckpoint.at);out.lastCheckpoint={...s.lastCheckpoint,ageMs:age,fresh:age<=maxAge};}
        out.lastTrigger=s.lastTrigger||null;out.lastDispatch=s.lastDispatch||null;
        if(s.lastDispatch?.sessionId){
          const markerPath=join(store,'automatic-dispatch',sessionKey(real,s.lastDispatch.sessionId)+'.json');
          let marker=null;try{if(existsSync(markerPath))marker=readPrivate(markerPath);}catch{}
          if(marker)out.lastDispatch={...out.lastDispatch,markerState:marker.state,threadId:marker.threadId??out.lastDispatch.threadId??null};
          if(marker?.state==='DETACHED'||marker?.state==='RUNNING'){
            let alive=false;if(Number.isInteger(marker.runnerPid)){try{process.kill(marker.runnerPid,0);alive=true;}catch{}}
            out.lastDispatch.runnerAlive=alive;
            if(!alive)out.warnings.push('DETACHED_RUNNER_EXITED_WITHOUT_RESULT: inspect receipts/leases, then use recover');
          }
        }
      }catch{out.warnings.push('HOOK_STATUS_UNREADABLE');}
    }
    if(existsSync(join(store,'leases',key+'.lock'))){out.lease={state:'HELD'};out.blockers.push('WORKTREE_ALREADY_LEASED');}
  }
  if(!out.lastCheckpoint)out.warnings.push('NO_CHECKPOINT_YET: no Claude Code hook has run in this worktree yet');
  else if(!out.lastCheckpoint.fresh)out.warnings.push('CHECKPOINT_STALE: a rate limit now would be refused until the next hook event');
  if(probeCodex){
    const run=args=>spawnSync(codexCommand,[...codexPrefixArgs,...args],{timeout:10000,encoding:'utf8',maxBuffer:8192,windowsHide:true});
    const v=run(['--version']),l=v.status===0?run(['login','status']):null;
    out.codex={available:v.status===0,version:v.status===0?String(v.stdout).trim().slice(0,60):null,loggedIn:l?.status===0};
    if(!out.codex.available)out.blockers.push('CODEX_EXECUTABLE_UNAVAILABLE');
    else if(!out.codex.loggedIn)out.blockers.push('CODEX_NOT_AUTHENTICATED');
  }
  out.blockers=out.blockers.map(code=>({code,category:categorizeHandoffError(code)}));
  out.ready=out.blockers.length===0;
  return out;
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
