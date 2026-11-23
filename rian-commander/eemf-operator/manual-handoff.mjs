/**
 * RIAN Agent Handoff P1: owner-confirmed, same-device manual Claude → Codex.
 * Local CLI only. No automatic hooks, no remote arbitrary command API.
 * Codex uses its own login, worktree-scoped sandbox, and stdin prompt.
 */
import {spawn,spawnSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {existsSync,readFileSync,realpathSync,mkdirSync,openSync,closeSync,writeFileSync,renameSync,rmSync,statSync,lstatSync,chmodSync,unlinkSync} from 'node:fs';
import {homedir} from 'node:os';
import {basename,isAbsolute,join,relative,sep} from 'node:path';
import {inspectWorktree,buildHandoff,saveLocalHandoff,planCodexHandoff} from './agent-handoff.mjs';

const fail=(code)=>{throw Error(code)};
const assert=(v,code)=>{if(!v)fail(code)};
const uuid=/^[a-f0-9-]{36}$/i;
const restricted=/-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:sk-(?:proj-)?|gh[pousr]_|xox[baprs]-)[A-Za-z0-9_\-]{12,}|\bBearer\s+[A-Za-z0-9._\-]{12,}|\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*['"]?\S{12,}/i;
const privates=/(?:^|[\s\/])(?:\.env|\.ssh|\.claude|\.codex|credentials\.json|auth\.json)(?:$|[\s\/])/i;
const now=()=>new Date().toISOString();
const fileJSON=(p)=>JSON.parse(readFileSync(p,'utf8'));
const sha=x=>createHash('sha256').update(x).digest('hex');
const defaultStore=()=>join(homedir(),'.rian-commander','handoffs');

function inside(root,path){
  const rel=relative(root,path);
  return rel===''||(rel!=='..'&&!rel.startsWith('..'+sep)&&!isAbsolute(rel));
}
function ensureStore(dir){
  assert(typeof dir==='string'&&isAbsolute(dir),'ABSOLUTE_STORE_REQUIRED');
  if(existsSync(dir))assert(!lstatSync(dir).isSymbolicLink(),'SYMLINK_STORE_DENIED');
  mkdirSync(dir,{recursive:true,mode:0o700});
  const real=realpathSync(dir);
  if(process.platform!=='win32')chmodSync(real,0o700);
  return real;
}
function atomicJSON(file,obj){
  const tmp=file+'.'+randomUUID()+'.tmp';
  try{
    const fd=openSync(tmp,'wx',0o600);
    try{writeFileSync(fd,JSON.stringify(obj,null,2)+'\n');}finally{closeSync(fd);}
    if(process.platform!=='win32')chmodSync(tmp,0o600);
    renameSync(tmp,file);
  }finally{if(existsSync(tmp))rmSync(tmp);}
}
function verifySafeNotes(data){
  const content=[data.task?.goal,...(data.task?.pendingSteps||[]),...(data.task?.tests||[])].join('\n');
  assert(!restricted.test(content)&&!privates.test(content),'SENSITIVE_HANDOFF_NOTES_DENIED');
}

/** Source-only checkpoint. No Claude or Codex subprocess is started. */
export function prepareManualHandoff({approvedRoot,worktree,taskId,goal,pendingSteps=[],testSummary=[],workspaceWrite=false,storeDir=defaultStore(),activeJobs=[]}){
  const repo=inspectWorktree({approvedRoot,worktree});
  const handoff=buildHandoff({taskId,goal,repo,pendingSteps,testSummary,event:'manual',
    ownerScope:{allowedProviders:['claude','codex'],workspaceWrite},activeJobs});
  verifySafeNotes(handoff);
  assert(handoff.repository.changed.every(x=>!/[\x00-\x1f\x7f]/.test(x.path)), 'CONTROL_CHARACTER_IN_GIT_PATH');
  const dir=ensureStore(storeDir);
  // Reject symlink escape before placing private checkpoint.
  const path=saveLocalHandoff(handoff,{directory:dir});
  return {path,handoff,commandPreview:planCodexHandoff(handoff,{ownerApproved:true}).args};
}

/** Read a checkpoint in an owner-controlled private folder, never from arbitrary paths. */
export function readManualCheckpoint({checkpointPath,storeDir=defaultStore()}){
  const dir=ensureStore(storeDir);
  assert(typeof checkpointPath==='string'&&isAbsolute(checkpointPath),'ABSOLUTE_CHECKPOINT_REQUIRED');
  assert(inside(dir,checkpointPath)&&basename(checkpointPath).endsWith('.json'),'CHECKPOINT_OUTSIDE_STORE');
  const st=lstatSync(checkpointPath,{throwIfNoEntry:false});
  assert(st&&st.isFile()&&!st.isSymbolicLink()&&st.size<=48_000,'UNSAFE_CHECKPOINT_FILE');
  if(process.platform!=='win32')assert((st.mode&0o077)===0,'CHECKPOINT_PERMISSIONS');
  const handoff=fileJSON(checkpointPath);
  assert(handoff?.schema==='rian-agent-handoff/v1'&&handoff?.state==='READY_FOR_CODEX'&&uuid.test(handoff.handoffId),'INVALID_HANDOFF');
  assert(basename(checkpointPath)===handoff.handoffId+'.json','CHECKPOINT_ID_MISMATCH');
  verifySafeNotes(handoff);
  return handoff;
}

function verifyGitUnchanged(handoff,approvedRoot){
  const current=inspectWorktree({approvedRoot,worktree:handoff.repository.worktree});
  const before=handoff.repository;
  assert(current.head===before.head&&current.branch===before.branch&&current.worktree===before.worktree,'GIT_HEAD_OR_BRANCH_CHANGED');
  // Preserve and separately review dirty uncommitted work rather than stashing it.
  const canon=x=>JSON.stringify((x||[]).map(f=>[f.status,f.path]).sort((a,b)=>a[1].localeCompare(b[1])));
  assert(current.dirty===before.dirty&&current.omittedSensitivePaths===before.omittedSensitivePaths&&canon(current.changed)===canon(before.changed),'GIT_WORKTREE_CHANGED_AFTER_CHECKPOINT');
  return current;
}
function minimalEnv(strictAuto=false){
  // Do not accidentally forward ANTHROPIC_ / CLAUDE_ / GitHub / cloud credentials.
  const allow=['PATH','Path','HOME','USER','LOGNAME','USERNAME','USERPROFILE','HOMEDRIVE','HOMEPATH','PROGRAMDATA','ComSpec','PATHEXT','SystemRoot','WINDIR','TMP','TEMP','TMPDIR','APPDATA','LOCALAPPDATA','XDG_CONFIG_HOME','XDG_CACHE_HOME','CODEX_HOME','OPENAI_API_KEY','OPENAI_BASE_URL','LANG','LC_ALL','TERM'];
  return Object.fromEntries(allow.filter(k=>typeof process.env[k]==='string'&&
    (!strictAuto||!['OPENAI_API_KEY','OPENAI_BASE_URL'].includes(k))).map(k=>[k,process.env[k]]));
}
function binaryArgs(prefix,args){
  assert(Array.isArray(prefix)&&prefix.every(x=>typeof x==='string'&&x.length<=500),'INVALID_TEST_EXECUTABLE_PREFIX');
  return [...prefix,...args];
}
function codexPreflight(command,prefix,repo,strictAuto=false){
  for(const args of [['--version'],['login','status']]){
    const result=spawnSync(command,binaryArgs(prefix,args),{cwd:repo,env:minimalEnv(strictAuto),windowsHide:true,timeout:10000,encoding:'utf8',maxBuffer:4096});
    assert(!result.error&&result.status===0,args[0]==='login'?'CODEX_NOT_AUTHENTICATED':'CODEX_EXECUTABLE_UNAVAILABLE');
  }
}
function validateExecutable(command){
  assert(typeof command==='string'&&command.length>0&&command.length<=512&&!/[\n\r\0]/.test(command),'INVALID_CODEX_COMMAND');
  // Normal CLI uses exactly 'codex'; injection of another binary is test-only.
  assert(command==='codex'||isAbsolute(command),'INVALID_CODEX_COMMAND');
}

/** Execute one Codex session, only on explicit P1 manual approval.
 * codexPrefixArgs is a test seam, never exposed in the user CLI.
 */
export async function executeManualHandoff(options={}){
  assert(options.ownerApproved===true&&options.claudeStopped===true,'OWNER_AND_QUIESCENCE_CONFIRMATION_REQUIRED');
  return executeApprovedHandoff(options);
}

/** Shared P1/P2 subprocess path. Callers must validate their own owner grant. */
export async function executeApprovedHandoff({checkpointPath,approvedRoot,storeDir=defaultStore(),ownerApproved=false,codexCommand='codex',codexPrefixArgs=[],timeoutMs=180_000,onProgress=()=>{},beforeDispatch=()=>{},strictAuto=false}={}){
  assert(ownerApproved===true,'OWNER_HANDOFF_APPROVAL_REQUIRED');
  assert(Number.isInteger(timeoutMs)&&timeoutMs>=1000&&timeoutMs<=1_800_000,'INVALID_RUNTIME_BUDGET');
  validateExecutable(codexCommand);
  const dir=ensureStore(storeDir);
  const handoff=readManualCheckpoint({checkpointPath,storeDir:dir});
  const ledgerDir=join(dir,'receipts'),leaseDir=join(dir,'leases');
  const receipt=join(ledgerDir,handoff.handoffId+'.json');
  assert(!existsSync(receipt),'HANDOFF_ALREADY_ATTEMPTED');
  const current=verifyGitUnchanged(handoff,approvedRoot);
  const plan=planCodexHandoff(handoff,{ownerApproved:true});
  mkdirSync(ledgerDir,{mode:0o700,recursive:true});mkdirSync(leaseDir,{mode:0o700,recursive:true});
  if(process.platform!=='win32'){chmodSync(ledgerDir,0o700);chmodSync(leaseDir,0o700);}
  const lock=join(leaseDir,sha(current.worktree)+'.lock');
  let fd;
  try{fd=openSync(lock,'wx',0o600);}catch(e){if(e?.code==='EEXIST')fail('WORKTREE_ALREADY_LEASED');throw e;}
  const attemptId=randomUUID();let spawned=false,uncertain=false,recordedFinal=false;
  try{
    writeFileSync(fd,JSON.stringify({attemptId,handoffId:handoff.handoffId,worktree:current.worktree,createdAt:now()}));
    closeSync(fd);fd=null;
    // Avoid launching after a checkpoint invalidation or login failure.
    verifyGitUnchanged(handoff,approvedRoot);
    codexPreflight(codexCommand,codexPrefixArgs,current.worktree,strictAuto);
    beforeDispatch();
    atomicJSON(receipt,{handoffId:handoff.handoffId,attemptId,state:'DISPATCHING',startedAt:now(),provider:'codex',worktree:current.worktree});
    const summary={handoffId:handoff.handoffId,attemptId,state:'UNKNOWN_DO_NOT_RETRY',events:0,malformed:0,threadId:null,exitCode:null,startedAt:now(),finishedAt:null,
      gitBefore:current.head,changedBefore:current.changed,testChecks:{passed:0,failed:0},commandChecks:{passed:0,failed:0}};
    const args=strictAuto?[
      // The approval policy is a top-level Codex flag, before `exec`.
      '-a','never',...plan.args.slice(0,-1),
      '--config','sandbox_workspace_write.network_access=false',
      '--config','sandbox_workspace_write.writable_roots=[]',
      '--config','sandbox_workspace_write.exclude_slash_tmp=true',
      '--config','sandbox_workspace_write.exclude_tmpdir_env_var=true',
      '--config','web_search="disabled"',
      '--config','apps._default.enabled=false',
      '--config','plugins._default.enabled=false',
      '--config','forced_login_method="chatgpt"','-'
    ]:plan.args;
    const proc=spawn(codexCommand,binaryArgs(codexPrefixArgs,args),{
      cwd:current.worktree,env:minimalEnv(strictAuto),stdio:['pipe','pipe','pipe'],windowsHide:true,shell:false
    });
    spawned=true;
    if(Number.isInteger(proc.pid)){
      atomicJSON(lock,{attemptId,handoffId:handoff.handoffId,worktree:current.worktree,createdAt:now(),childPid:proc.pid});
      atomicJSON(receipt,{handoffId:handoff.handoffId,attemptId,state:'RUNNING',startedAt:summary.startedAt,
        provider:'codex',worktree:current.worktree,childPid:proc.pid});
    }
    proc.stdin.on('error',()=>{});
    proc.stdin.end(plan.stdin);
    let buffer='',byteCount=0;
    const parse=(line)=>{
      if(!line)return;
      summary.events++;
      try{
        const event=JSON.parse(line);
        if(event.type==='thread.started'&&typeof event.thread_id==='string'&&uuid.test(event.thread_id))summary.threadId=event.thread_id;
        if(event.type==='turn.completed')summary.turnCompleted=true;
        if(event.type==='item.completed'&&event.item?.type==='command_execution'){
          const ok=event.item.exit_code===0;
          summary.commandChecks[ok?'passed':'failed']++;
          const command=String(event.item.command||'');
          if(/(?:^|[\s'";])(?:node(?:\.exe)?\s+--test|npm\s+test|pytest|python(?:3)?(?:\.exe)?\s+-m\s+unittest)\b/i.test(command))
            summary.testChecks[ok?'passed':'failed']++;
        }
        if(event.type==='turn.failed'){
          summary.turnFailed=true;
          const reason=String(event.error?.message||event.error?.code||'').slice(0,500);
          summary.failureKind=/usage.limit|quota|insufficient.quota|rate.limit/i.test(reason)?'USAGE_LIMIT':
            /network|connect|timeout|socket|dns|econn/i.test(reason)?'NETWORK_UNCERTAIN':'PROVIDER_FAILED';
        }
      }catch{summary.malformed++;}
      try{onProgress({handoffId:summary.handoffId,attemptId:summary.attemptId,state:'RUNNING',events:summary.events,
        threadId:summary.threadId,failureKind:summary.failureKind||null});}catch{}
    };
    proc.stdout.on('data',part=>{
      byteCount+=part.byteLength;
      if(byteCount>4*1024*1024){uncertain=true;proc.kill();return;}
      buffer+=part.toString('utf8');
      while(buffer.includes('\n')){
        const ix=buffer.indexOf('\n');parse(buffer.slice(0,ix));buffer=buffer.slice(ix+1);
        if(buffer.length>150000){uncertain=true;proc.kill();break;}
      }
    });
    // Never store raw stderr or JSON events: tool results may contain credentials.
    proc.stderr.on('data',()=>{});
    const outcome=await new Promise(resolve=>{
      let settled=false,killTimer,forceTimer;
      const finish=value=>{
        if(settled)return;
        settled=true;clearTimeout(timeout);clearTimeout(killTimer);clearTimeout(forceTimer);resolve(value);
      };
      const timeout=setTimeout(()=>{
        uncertain=true;proc.kill();
        killTimer=setTimeout(()=>{
          proc.kill('SIGKILL');
          forceTimer=setTimeout(()=>{
            proc.stdout.destroy();proc.stderr.destroy();proc.unref();
            finish({code:null,signal:'TIMEOUT_UNCONFIRMED'});
          },2000);
        },1000);
      },timeoutMs);
      proc.once('error',err=>finish({error:err,code:null,signal:null}));
      proc.once('close',(code,signal)=>finish({code,signal}));
    });
    if(buffer)parse(buffer.slice(0,120000));
    summary.finishedAt=now();summary.exitCode=outcome.code;
    summary.state=uncertain||outcome.signal||summary.failureKind==='NETWORK_UNCERTAIN'?'UNKNOWN_DO_NOT_RETRY':
      outcome.code===0&&summary.turnCompleted&&!summary.turnFailed?'COMPLETED':'FAILED';
    try{
      const after=inspectWorktree({approvedRoot,worktree:current.worktree});
      summary.gitAfter=after.head;summary.changedAfter=after.changed;
    }catch{summary.gitAfter='UNVERIFIED';summary.changedAfter=[];}
    atomicJSON(receipt,summary);recordedFinal=true;
    // Unknown state deliberately retains lock: a reviewer must check the process
    // before starting another provider on this worktree.
    if(summary.state==='UNKNOWN_DO_NOT_RETRY')return {...summary,lockRetained:true};
    return {...summary,lockRetained:false};
  }finally{
    if(fd!==undefined&&fd!==null)closeSync(fd);
    if(!recordedFinal && (spawned||existsSync(receipt))){
      // A child may have been launched; retain the lease until a person verifies.
      uncertain=true;
    }
    if(!uncertain&&existsSync(lock)){
      try{const record=fileJSON(lock);if(record.attemptId===attemptId)unlinkSync(lock);}catch{}
    }
  }
}
