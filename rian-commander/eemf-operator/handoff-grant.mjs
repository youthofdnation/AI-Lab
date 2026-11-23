/**
 * P2.2 project standing grant (Issue #9): ONE owner approval per device + Git worktree, then
 * unattended Claude -> Codex handoffs inside that scope, without a terminal phrase per task.
 *
 * The grant fixes: device, exact worktree, providers, sandbox permission (workspace write only;
 * never network, push, deploy or credentials), expiry (<= 30 days), total handoffs (<= 20) and the
 * per-run time limit (<= 30 min). The task is NOT part of the grant: it is the owner's last prompt
 * to Claude Code in that worktree, captured locally by the official UserPromptSubmit hook.
 * Anything outside the scope (other worktree or device, expired, revoked, exhausted) fails closed.
 */
import {spawnSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {chmodSync,closeSync,existsSync,lstatSync,mkdirSync,openSync,readFileSync,readdirSync,realpathSync,renameSync,rmSync,writeFileSync} from 'node:fs';
import {hostname} from 'node:os';
import {basename,dirname,isAbsolute,join,relative,sep} from 'node:path';

export const GRANT_LIMITS=Object.freeze({maxRuns:20,maxDays:30,maxRunMinutes:30});
const assert=(v,c)=>{if(!v)throw Error(c);};
const hash=x=>createHash('sha256').update(x).digest('hex');
const SECRET=/-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:sk-(?:proj-)?|gh[pousr]_|xox[baprs]-)[A-Za-z0-9_-]{12,}|\bBearer\s+[A-Za-z0-9._-]{12,}|\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*['"]?\S{12,}/i;

function privateDir(dir){
  if(existsSync(dir))assert(!lstatSync(dir).isSymbolicLink(),'SYMLINK_STORE_DENIED');
  mkdirSync(dir,{recursive:true,mode:0o700});
  if(process.platform!=='win32')chmodSync(dir,0o700);
  return dir;
}
function atomic(file,obj){
  const temp=file+'.'+randomUUID()+'.tmp';
  try{
    const fd=openSync(temp,'wx',0o600);
    try{writeFileSync(fd,JSON.stringify(obj,null,2)+'\n');}finally{closeSync(fd);}
    renameSync(temp,file);
  }finally{if(existsSync(temp))rmSync(temp);}
}
const grantFile=(store,worktree)=>join(store,'grants',hash(worktree)+'.json');
function canonicalPath(path){
  if(existsSync(path))return realpathSync(path);
  const parent=dirname(path);
  return join(canonicalPath(parent),basename(path));
}

/** Check the Git root without comparing Git's POSIX-formatted Windows paths to OS realpaths.
 * Git's --show-prefix is empty exactly at the worktree root on all three OSes.
 */
function isGitRoot(dir){
  const r=spawnSync('git',['-C',dir,'rev-parse','--is-inside-work-tree','--show-prefix'],
    {encoding:'utf8',timeout:10000});
  assert(!r.error&&r.status===0,'GRANT_WORKTREE_NOT_GIT');
  const lines=r.stdout.replace(/\r/g,'').split('\n');
  return lines[0]==='true'&&lines[1]==='';
}

/** Builds (does not store) the grant the owner is asked to approve. */
export function planGrant({worktree,approvedRoot,runs=5,days=7,runMinutes=20,workspaceWrite=true,device=hostname(),now=Date.now()}){
  assert(typeof worktree==='string'&&isAbsolute(worktree),'GRANT_WORKTREE_REQUIRED');
  const real=realpathSync(worktree);
  assert(isGitRoot(real),'GRANT_WORKTREE_MUST_BE_GIT_ROOT');
  const root=approvedRoot?realpathSync(approvedRoot):real,rel=relative(root,real);
  assert(rel===''||(rel!=='..'&&!rel.startsWith('..'+sep)&&!isAbsolute(rel)),'GRANT_WORKTREE_OUTSIDE_ROOT');
  for(const [v,max] of [[runs,GRANT_LIMITS.maxRuns],[days,GRANT_LIMITS.maxDays],[runMinutes,GRANT_LIMITS.maxRunMinutes]])
    assert(Number.isInteger(v)&&v>=1&&v<=max,'GRANT_LIMIT_INVALID');
  assert(typeof workspaceWrite==='boolean','GRANT_LIMIT_INVALID');
  return {schema:'rian-handoff-grant/v1',grantId:randomUUID(),device,worktree:real,approvedRoot:root,
    providers:['claude','codex'],taskSource:'claude-last-user-prompt',
    permissions:{workspaceWrite,network:false,push:false,deploy:false,credentials:false},
    maxRuns:runs,runTimeoutMs:runMinutes*60_000,checkpointMaxAgeMs:900_000,
    createdAt:new Date(now).toISOString(),expiresAt:new Date(now+days*86_400_000).toISOString()};
}

/** Homebrew's process.execPath is the versioned Cellar path, which `brew upgrade` deletes; a hook
 * pinned to it fails on every event and the handoff never runs. Its opt/ link survives upgrades. */
export function stableNodeCommand(execPath=process.execPath,exists=existsSync){
  const m=/^(.+)\/Cellar\/(node(?:@\d+)?)\/[^/]+\/bin\/node$/.exec(execPath);
  const opt=m&&`${m[1]}/opt/${m[2]}/bin/node`;
  return opt&&exists(opt)?opt:execPath;
}

/** Output-only Claude Code project-local hook configuration for the existing grant receiver. */
export function planGrantHooks({worktree,runtime,store,nodeCommand=stableNodeCommand()}){
  const real=planGrant({worktree}).worktree;
  assert(typeof runtime==='string'&&isAbsolute(runtime),'INSTALL_RUNTIME_ABSOLUTE_REQUIRED');
  const runtimeStat=lstatSync(runtime);
  assert(runtimeStat.isFile()&&!runtimeStat.isSymbolicLink(),'INSTALL_RUNTIME_UNSAFE');
  const fixed=realpathSync(runtime),rel=relative(real,fixed);
  assert(rel==='..'||rel.startsWith('..'+sep)||isAbsolute(rel),'INSTALL_RUNTIME_INSIDE_WORKTREE');
  assert(fixed.endsWith(sep+'automatic-handoff-cli.mjs'),'INSTALL_RUNTIME_NAME_INVALID');
  assert(typeof nodeCommand==='string'&&isAbsolute(nodeCommand),'INSTALL_NODE_ABSOLUTE_REQUIRED');
  const args=[fixed,'hook-grant'];
  if(store!==undefined){
    assert(typeof store==='string'&&isAbsolute(store),'INSTALL_STORE_ABSOLUTE_REQUIRED');
    const storeRel=relative(real,canonicalPath(store));
    assert(storeRel==='..'||storeRel.startsWith('..'+sep)||isAbsolute(storeRel),'INSTALL_STORE_INSIDE_WORKTREE');
    args.push('--store',store);
  }
  const hook=(timeout)=>[{hooks:[{type:'command',command:nodeCommand,args:[...args],timeout}]}];
  const settings={hooks:{SessionStart:hook(20),UserPromptSubmit:hook(20),PostToolUse:hook(20),
    PostToolUseFailure:hook(20),StopFailure:[{matcher:'rate_limit',hooks:[{type:'command',command:nodeCommand,args:[...args],timeout:30}]}]}};
  const settingsPath=join(real,'.claude','settings.local.json');
  return {state:'PREVIEW_ONLY',worktree:real,settingsPath,existingSettings:existsSync(settingsPath),
    settings,requirements:['Review and merge with any existing project-local settings; do not overwrite them.',
      'Use a fixed, reviewed runtime copy outside the editable worktree.',
      'An active P2.2 grant for this exact worktree and device is required before handoff.']};
}

export function grantSummary(g){
  return ['RIAN Commander - Claude Code -> Codex 자동 인계 허가 (프로젝트 최초 1회)','',
    '장치: '+g.device,'작업 폴더: '+g.worktree,
    '허용: Claude Code가 사용량 한도로 멈추면 Codex가 이 폴더에서 마지막 요청을 이어서 개발·테스트',
    'Codex 권한: '+(g.permissions.workspaceWrite?'이 폴더 안 파일 수정':'읽기 전용')+' / 네트워크·푸시·배포·인증정보 접근 없음',
    '총 인계 횟수: 최대 '+g.maxRuns+'회 / 1회 실행: 최대 '+Math.round(g.runTimeoutMs/60000)+'분',
    '유효기간: '+g.expiresAt.slice(0,10)+'까지 (언제든 철회 가능)',
    '보내는 정보: 마지막 요청 문장과 Git 변경 경로 목록 (비밀값 패턴이 있으면 인계 거부)'];
}

/**
 * Owner confirmation by a real click in a native OS dialog (macOS / Windows). Declining, closing
 * or ignoring it for 3 minutes is a refusal. Returns 'APPROVED' only for an explicit click.
 */
export function confirmGrantByDialog(g,{platform=process.platform,run=spawnSync}={}){
  const text=grantSummary(g).join('\n');
  let r;
  if(platform==='darwin'){
    r=run('/usr/bin/osascript',['-e','on run argv','-e',
      'display dialog (item 1 of argv) with title "RIAN Commander" buttons {"거절", "승인"} default button "거절" cancel button "거절" with icon caution giving up after 180',
      '-e','end run',text],{encoding:'utf8',timeout:200_000});
    return r.status===0&&/button returned:승인/.test(r.stdout||'')&&!/gave up:true/.test(r.stdout||'')?'APPROVED':'DECLINED';
  }
  if(platform==='win32'){
    r=run('powershell.exe',['-NoProfile','-NonInteractive','-Command',
      'Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show($env:RIAN_GRANT_TEXT,"RIAN Commander","YesNo","Warning","Button2")'],
      {encoding:'utf8',timeout:200_000,env:{...process.env,RIAN_GRANT_TEXT:text}});
    return r.status===0&&String(r.stdout).trim()==='Yes'?'APPROVED':'DECLINED';
  }
  throw Error('OWNER_DIALOG_UNAVAILABLE');
}

export function saveGrant({grant,store,approvedVia}){
  assert(['macos-dialog','windows-dialog','terminal'].includes(approvedVia),'GRANT_APPROVAL_METHOD_INVALID');
  privateDir(join(store,'grants'));
  const record={...grant,approvedVia,approvedAt:new Date().toISOString(),revoked:false};
  atomic(grantFile(store,grant.worktree),record);
  return record;
}

/** Valid, unexpired, unrevoked grant for this device and exact worktree, or a precise refusal. */
export function readGrant({worktree,store,now=Date.now(),device=hostname()}){
  const file=grantFile(store,worktree);
  assert(existsSync(file),'GRANT_NOT_FOUND');
  const st=lstatSync(file);
  assert(st.isFile()&&!st.isSymbolicLink()&&st.size<=16_000,'GRANT_RECORD_UNSAFE');
  if(process.platform!=='win32')assert((st.mode&0o077)===0,'GRANT_RECORD_PERMISSIONS');
  const bytes=readFileSync(file),g=JSON.parse(bytes);
  assert(g.schema==='rian-handoff-grant/v1'&&g.worktree===worktree,'GRANT_WORKTREE_MISMATCH');
  assert(g.revoked!==true,'GRANT_REVOKED');
  assert(Date.parse(g.expiresAt)>now,'GRANT_EXPIRED');
  assert(g.device===device,'GRANT_DEVICE_MISMATCH');
  assert(g.permissions?.network===false&&g.permissions?.push===false&&g.permissions?.deploy===false&&g.permissions?.credentials===false,'GRANT_SCOPE_INVALID');
  assert(Number.isInteger(g.maxRuns)&&g.maxRuns>=1&&g.maxRuns<=GRANT_LIMITS.maxRuns&&
    Number.isInteger(g.runTimeoutMs)&&g.runTimeoutMs>=60_000&&g.runTimeoutMs<=GRANT_LIMITS.maxRunMinutes*60_000,'GRANT_SCOPE_INVALID');
  return {grant:g,digest:hash(JSON.stringify({...g,revoked:false}))};
}

/** Revocation never needs a confirmation and takes effect before the next trigger or run. */
export function revokeGrant({worktree,store,reason='owner revoked'}){
  const file=grantFile(store,worktree);
  assert(existsSync(file),'GRANT_NOT_FOUND');
  const g=JSON.parse(readFileSync(file));
  atomic(file,{...g,revoked:true,revokedAt:new Date().toISOString(),revokeReason:String(reason).slice(0,200)});
  return {state:'REVOKED',grantId:g.grantId};
}

export function grantRunsUsed({grant,store}){
  const dir=join(store,'grant-runs',grant.grantId);
  return existsSync(dir)?readdirSync(dir).filter(f=>/^\d+\.json$/.test(f)).length:0;
}
/** Atomically takes one of the grant's runs (exclusive file per run slot). */
export function consumeGrantRun({grant,store,handoffId}){
  const dir=privateDir(join(store,'grant-runs',grant.grantId));
  for(let i=1;i<=grant.maxRuns;i++){
    let fd;
    try{fd=openSync(join(dir,i+'.json'),'wx',0o600);}catch(e){if(e?.code==='EEXIST')continue;throw e;}
    try{writeFileSync(fd,JSON.stringify({run:i,handoffId,at:new Date().toISOString()}));}finally{closeSync(fd);}
    return i;
  }
  throw Error('GRANT_RUNS_EXHAUSTED');
}

/** Local, size-bounded copy of the owner's prompt. Secret-looking prompts are never stored or sent. */
export function capturePrompt(prompt){
  if(typeof prompt!=='string')return {prompt:null,rejected:null};
  const clean=prompt.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g,'').trim();
  if(!clean)return {prompt:null,rejected:null};
  if(SECRET.test(clean))return {prompt:null,rejected:'CHECKPOINT_PROMPT_SENSITIVE'};
  return {prompt:clean.length>3000?clean.slice(0,3000)+' …(truncated)':clean,rejected:null};
}

/** The task Codex receives: continue the owner's last request, inside the grant's limits. */
export function taskFromPrompt(prompt){
  assert(typeof prompt==='string'&&prompt.trim(),'CHECKPOINT_NO_TASK_PROMPT');
  return {taskId:'prompt_'+hash(prompt).slice(0,24),
    goal:'Claude Code stopped on a usage limit while working on the owner request below in this repository. '+
      'Continue it from the current working tree: Claude may have left uncommitted partial work, keep it. '+
      'Finish the request, run the relevant tests, and leave every change uncommitted for owner review. '+
      'Do not push, deploy, use the network, read credentials, or delete files the request does not need.\n\n'+
      'Owner request to Claude Code:\n'+prompt,
    pendingSteps:['Inspect git status and the partial work','Complete the owner request','Run the relevant tests','Summarize what changed and what is left'],
    testSummary:[]};
}
