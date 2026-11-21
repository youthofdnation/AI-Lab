/**
 * RIAN Commander: cross-provider developer handoff foundation.
 * Source-only. Does NOT launch Claude/Codex, install hooks, or modify remote PCs.
 */
import {execFileSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {chmodSync, existsSync, mkdirSync, realpathSync, renameSync, rmSync, writeFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {isAbsolute, join, relative, sep} from 'node:path';

const ACTIVE = new Set(['RUNNING','CANCEL_REQUESTED','UNKNOWN','UNKNOWN_DO_NOT_RETRY','IN_FLIGHT']);
const GIT_SHA = /^[a-f0-9]{40}$/i;
const SENSITIVE = /(^|[\\/])(?:\.env(?:\.[^\\/]*)?|\.ssh|\.aws|\.gnupg|\.codex|\.claude|secrets?|credentials?|\.git)(?=$|[\\/])|(?:token|password|secret|private[-_]?key|auth\.json|\.pem|\.p12|\.pfx)/i;
const check = (yes, code) => { if (!yes) throw new Error(code); };
const safeText = (v,n) => {
  check(typeof v === 'string' && v.trim().length > 0 && v.length <= n && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(v),'INVALID_HANDOFF_TEXT');
  return v.trim();
};

/** Official Claude Code StopFailure event, not a guessed percentage or GUI scrape. */
export function classifyClaudeStop(event) {
  if (!event || event.hook_event_name !== 'StopFailure') return 'NO_TRIGGER';
  if (event.error === 'rate_limit') return 'CLAUDE_RATE_LIMIT';
  if (['authentication_failed','account_on_hold','billing_error'].includes(event.error)) return 'OWNER_ATTENTION_REQUIRED';
  return 'NO_TRIGGER';
}

function git(root,...args) {
  return execFileSync('git',['-C',root,...args],{encoding:'utf8',maxBuffer:1024*1024,timeout:12000});
}

/** Inspect an owner-allowlisted Git worktree without reading diff content. */
export function inspectWorktree({approvedRoot,worktree}) {
  check(typeof approvedRoot === 'string' && isAbsolute(approvedRoot),'APPROVED_ROOT_REQUIRED');
  check(typeof worktree === 'string' && isAbsolute(worktree),'ABSOLUTE_WORKTREE_REQUIRED');
  const allowed=realpathSync(approvedRoot),actual=realpathSync(worktree);
  const rel=relative(allowed,actual);
  check(rel==='' || (rel!=='..' && !rel.startsWith('..'+sep) && !isAbsolute(rel)),'WORKTREE_OUTSIDE_OWNER_SCOPE');
  check(realpathSync(git(actual,'rev-parse','--show-toplevel').trim())===actual,'WORKTREE_MUST_BE_GIT_ROOT');
  const head=git(actual,'rev-parse','HEAD').trim();
  check(GIT_SHA.test(head),'INVALID_GIT_HEAD');
  const branch=git(actual,'branch','--show-current').trim()||'(detached)';
  const fields=git(actual,'status','--porcelain=v1','-z','--untracked-files=normal').split('\0').filter(Boolean);
  const changed=[]; let omittedSensitivePaths=0;
  for(let i=0;i<fields.length;i++){
    const item=fields[i]; if(item.length<4)continue;
    const status=item.slice(0,2),path=item.slice(3);
    if(status.includes('R')||status.includes('C'))i++; // rename/copy has second -z path
    if(SENSITIVE.test(path)){omittedSensitivePaths++;continue;}
    changed.push({status,path});
    check(changed.length<=200,'CHANGED_FILE_LIMIT');
  }
  return {worktree:actual,head,branch,changed,omittedSensitivePaths,dirty:fields.length>0};
}

/** Fail closed for unapproved providers, unknown in-flight work and risky paths. */
export function buildHandoff({taskId,goal,repo,pendingSteps=[],testSummary=[],event,ownerScope,activeJobs=[]}){
  check(typeof taskId==='string'&&/^[A-Za-z0-9_-]{8,80}$/.test(taskId),'INVALID_TASK_ID');
  check(ownerScope&&ownerScope.allowedProviders?.includes('claude')&&ownerScope.allowedProviders?.includes('codex'),'PROVIDER_SCOPE_NOT_APPROVED');
  check(typeof ownerScope.workspaceWrite==='boolean','INVALID_OWNER_SCOPE');
  check(Array.isArray(activeJobs)&&activeJobs.length<=100,'INVALID_ACTIVE_JOBS');
  check(!activeJobs.some(j=>ACTIVE.has(j.state)),'ACTIVE_JOB_CANNOT_HANDOFF');
  check(repo&&typeof repo.worktree==='string'&&isAbsolute(repo.worktree)&&GIT_SHA.test(repo.head),'INVALID_REPO');
  check(Array.isArray(repo.changed)&&repo.changed.length<=200&&repo.changed.every(f=>f&&typeof f.status==='string'&&/^[ MADRCU?!]{2}$/.test(f.status)&&typeof f.path==='string'&&f.path.length<=512&&!SENSITIVE.test(f.path)&&!isAbsolute(f.path)&&!f.path.split(/[\\/]/).includes('..')),'UNSAFE_REPO_METADATA');
  check(Array.isArray(pendingSteps)&&pendingSteps.length<=20,'INVALID_PENDING_STEPS');
  check(Array.isArray(testSummary)&&testSummary.length<=30,'INVALID_TEST_RESULTS');
  const trigger=event==='manual'?'MANUAL_REQUEST':classifyClaudeStop(event);
  check(['CLAUDE_RATE_LIMIT','MANUAL_REQUEST'].includes(trigger),'UNSUPPORTED_HANDOFF_TRIGGER');
  return {
    schema:'rian-agent-handoff/v1',taskId,handoffId:randomUUID(),createdAt:new Date().toISOString(),
    trigger,from:'claude',to:'codex',state:'READY_FOR_CODEX',
    repository:{worktree:repo.worktree,head:repo.head,branch:repo.branch,
      dirty:!!repo.dirty,changed:repo.changed,omittedSensitivePaths:repo.omittedSensitivePaths||0},
    task:{goal:safeText(goal,4000),pendingSteps:pendingSteps.map(x=>safeText(x,500)),tests:testSummary.map(x=>safeText(x,500))},
    authorization:{workspaceWrite:ownerScope.workspaceWrite,ownerApprovalNeededForSensitiveActions:true}
  };
}

/** Local-only checkpoint (0700 directory, 0600 file on POSIX); no Git commit. */
export function saveLocalHandoff(handoff,{directory=join(homedir(),'.rian-commander','handoffs')}={}){
  check(handoff?.schema==='rian-agent-handoff/v1'&&handoff.state==='READY_FOR_CODEX','INVALID_HANDOFF');
  check(typeof directory==='string'&&isAbsolute(directory),'ABSOLUTE_STORE_REQUIRED');
  mkdirSync(directory,{recursive:true,mode:0o700});
  if(process.platform!=='win32')chmodSync(directory,0o700);
  const dest=join(directory,handoff.handoffId+'.json');
  check(!existsSync(dest),'HANDOFF_ALREADY_EXISTS');
  const temp=join(directory,'.'+handoff.handoffId+'.'+randomUUID()+'.tmp');
  try{
    writeFileSync(temp,JSON.stringify(handoff,null,2)+'\n',{mode:0o600,flag:'wx'});
    if(process.platform!=='win32')chmodSync(temp,0o600);
    renameSync(temp,dest);
  }finally{if(existsSync(temp))rmSync(temp);}
  return dest;
}

/** A launch PLAN only, not execution; agent must enforce scoped approval + lease. */
export function planCodexHandoff(handoff,{ownerApproved=false}={}){
  check(handoff?.schema==='rian-agent-handoff/v1'&&handoff.state==='READY_FOR_CODEX','HANDOFF_NOT_READY');
  check(ownerApproved===true,'OWNER_HANDOFF_APPROVAL_REQUIRED');
  const permission=handoff.authorization.workspaceWrite?'workspace-write':'read-only';
  const r=handoff.repository;
  const prompt=[
    'Continue an owner-approved RIAN development task previously worked on by Claude Code.',
    'This is a new Codex session; do not claim to have the original Claude conversation.',
    'First review Git status, diffs, build instructions and active processes. Preserve all staged, unstaged and untracked work.',
    'Do not push, delete, deploy, modify secrets or interrupt other processes without separate approval.',
    'If a concurrent writer, unknown job or risky change is detected, stop for owner review.',
    'Goal: '+handoff.task.goal,'Checkpoint HEAD: '+r.head+'; branch: '+r.branch,
    'Modified paths (metadata only): '+JSON.stringify(r.changed),
    'Remaining tasks: '+JSON.stringify(handoff.task.pendingSteps),
    'Known tests: '+JSON.stringify(handoff.task.tests),
    'Finally report changes, tests, Git HEAD and unresolved issues without exposing secrets.'
  ].join('\n');
  return {command:'codex',args:['exec','--json','--sandbox',permission,'--cd',r.worktree,'-'],
    stdin:prompt,handoffId:handoff.handoffId};
}
