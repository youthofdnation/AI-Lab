import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {existsSync,mkdirSync,mkdtempSync,readFileSync,rmSync,statSync,writeFileSync} from 'node:fs';
import {tmpdir,hostname} from 'node:os';
import {join} from 'node:path';
import {createProjectGrant,grantHandoffStatus,handleClaudeHook,revokeProjectGrant,runDetachedDispatch} from './automatic-handoff.mjs';
import {confirmGrantByDialog,planGrant,readGrant,capturePrompt} from './handoff-grant.mjs';

function fixture(t,{runs=3}={}){
  const root=mkdtempSync(join(tmpdir(),'rian-grant-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const repo=join(root,'repo'),store=join(root,'store'),other=join(root,'other');
  for(const d of [repo,other])mkdirSync(d);
  const git=(dir,...a)=>execFileSync('git',['-C',dir,...a],{encoding:'utf8'}).trim();
  for(const d of [repo,other]){git(d,'init','-q');writeFileSync(join(d,'README.md'),'base\n');git(d,'add','README.md');
    git(d,'-c','user.name=CI','-c','user.email=ci@example.invalid','commit','-qm','initial');}
  writeFileSync(join(repo,'CLAUDE-PARTIAL.md'),'untracked partial work\n');
  const fake=join(root,'fake-codex.mjs');
  writeFileSync(fake,[
    "import {writeFileSync} from 'node:fs';import {join} from 'node:path';",
    "const a=process.argv.slice(2);",
    "if(a[0]==='--version'){console.log('codex-cli-test 1.0');process.exit(0)}",
    "if(a[0]==='login'){process.exit(0)}",
    "if(a[0]!=='-a'||a[1]!=='never'||a[2]!=='exec'||!a.includes('sandbox_workspace_write.network_access=false'))process.exit(4);",
    "let p='';for await(const c of process.stdin)p+=c;",
    "const m=/Owner request to Claude Code:\\n([^\\n]+)/.exec(p);if(!m)process.exit(3);",
    "const wd=a[a.indexOf('--cd')+1];",
    "console.log(JSON.stringify({type:'thread.started',thread_id:'12345678-aaaa-4bbb-8ccc-123456789abc'}));",
    "writeFileSync(join(wd,'CODEX-'+m[1].split(' ')[0]+'.md'),m[1]+'\\n');",
    "console.log(JSON.stringify({type:'turn.completed'}));"].join('\n')+'\n');
  const codex={codexCommand:process.execPath,codexPrefixArgs:[fake]};
  let asked=0;
  const confirm=async()=>{asked++;return 'terminal';};
  const ev=(hook_event_name,session_id,extra={})=>({hook_event_name,session_id,cwd:repo,...extra});
  const hook=(e,opts={})=>handleClaudeHook({event:e,grant:true,storeDir:store,...codex,...opts});
  return {root,repo,store,other,git,codex,confirm,asked:()=>asked,ev,hook,runs};
}

test('one owner approval, then two different tasks are handed off with no further input',async t=>{
  const f=fixture(t);
  const g=await createProjectGrant({worktree:f.repo,storeDir:f.store,runs:3,days:7,runMinutes:5,confirm:f.confirm});
  assert.equal(f.asked(),1);assert.equal(g.device,hostname());
  if(process.platform!=='win32')assert.equal(statSync(join(f.store,'grants')).mode&0o777,0o700);
  for(const [session,prompt] of [['session-aaa-111','ALPHA implement the parser'],['session-bbb-222','BETA add the parser tests']]){
    await f.hook(f.ev('SessionStart',session));
    assert.equal((await f.hook(f.ev('UserPromptSubmit',session,{prompt}))).taskCaptured,true);
    await f.hook(f.ev('PostToolUse',session));
    const r=await f.hook(f.ev('StopFailure',session,{error:'rate_limit'}));
    assert.equal(r.state,'COMPLETED',prompt);
    assert.equal(readFileSync(join(f.repo,'CODEX-'+prompt.split(' ')[0]+'.md'),'utf8'),prompt+'\n','Codex received the owner request');
  }
  assert.equal(f.asked(),1,'no second approval for a second task');
  assert.equal(readFileSync(join(f.repo,'CLAUDE-PARTIAL.md'),'utf8'),'untracked partial work\n','Claude partial work kept');
  const s=grantHandoffStatus({worktree:f.repo,storeDir:f.store,probeCodex:false});
  assert.equal(s.grant.state,'ACTIVE');assert.equal(s.grant.runsUsed,2);assert.equal(s.grant.runsLeft,1);
  assert.equal(s.lastDispatch.markerState,'COMPLETED');assert.equal(s.ready,true);
});

test('replays, other worktrees, revocation, expiry, exhaustion and secrets fail closed',async t=>{
  const f=fixture(t);
  await createProjectGrant({worktree:f.repo,storeDir:f.store,runs:2,days:1,runMinutes:5,confirm:f.confirm});
  const run=async(session,prompt,opts)=>{await f.hook(f.ev('UserPromptSubmit',session,{prompt}));return f.hook(f.ev('StopFailure',session,{error:'rate_limit'}),opts);};
  assert.equal((await run('session-one-111','GAMMA first task')).state,'COMPLETED');
  await assert.rejects(()=>run('session-two-222','GAMMA first task'),/PROJECT_TASK_ALREADY_ATTEMPTED/,'same request is never replayed');
  await assert.rejects(()=>f.hook(f.ev('StopFailure','session-one-111',{error:'rate_limit'})),/AUTOMATIC_DISPATCH_ALREADY_ATTEMPTED/);
  await f.hook(f.ev('UserPromptSubmit','session-three-333'));
  await assert.rejects(()=>f.hook(f.ev('StopFailure','session-three-333',{error:'rate_limit'})),/CHECKPOINT_NO_TASK_PROMPT/);
  assert.equal(capturePrompt('deploy with api_key=sk-proj-abcdefghijklmnopqrstuv').rejected,'CHECKPOINT_PROMPT_SENSITIVE');
  await f.hook(f.ev('UserPromptSubmit','session-four-444',{prompt:'use password: hunter2hunter2hunter2 to log in'}));
  await assert.rejects(()=>f.hook(f.ev('StopFailure','session-four-444',{error:'rate_limit'})),/CHECKPOINT_PROMPT_SENSITIVE/);
  assert.equal((await run('session-five-555','DELTA second task')).state,'COMPLETED');
  await assert.rejects(()=>run('session-six-666','EPSILON third task'),/GRANT_RUNS_EXHAUSTED/);
  await assert.rejects(()=>handleClaudeHook({event:{...f.ev('SessionStart','session-x-777'),cwd:f.other},grant:true,storeDir:f.store}),/GRANT_NOT_FOUND/);
  revokeProjectGrant({worktree:f.repo,storeDir:f.store,reason:'test'});
  await assert.rejects(()=>f.hook(f.ev('SessionStart','session-seven-888')),/GRANT_REVOKED/);
  const s=grantHandoffStatus({worktree:f.repo,storeDir:f.store,probeCodex:false});
  assert.equal(s.ready,false);assert.deepEqual(s.blockers[0],{code:'GRANT_REVOKED',category:'APPROVAL'});
  const plan=planGrant({worktree:f.repo,runs:1,days:1,runMinutes:1});
  assert.throws(()=>readGrant({worktree:plan.worktree,store:f.store,now:Date.now()+3*86_400_000}),/GRANT_REVOKED|GRANT_EXPIRED/);
});

test('expired or foreign-device grants refuse; revoke between trigger and run stops Codex',async t=>{
  const f=fixture(t);
  await createProjectGrant({worktree:f.repo,storeDir:f.store,runs:3,days:1,runMinutes:5,confirm:f.confirm});
  const real=readGrant({worktree:planGrant({worktree:f.repo}).worktree,store:f.store}).grant;
  assert.throws(()=>readGrant({worktree:real.worktree,store:f.store,now:Date.now()+2*86_400_000}),/GRANT_EXPIRED/);
  assert.throws(()=>readGrant({worktree:real.worktree,store:f.store,device:'another-mac'}),/GRANT_DEVICE_MISMATCH/);
  await f.hook(f.ev('UserPromptSubmit','session-det-111',{prompt:'ZETA detached task'}));
  const r=await f.hook(f.ev('StopFailure','session-det-111',{error:'rate_limit'}),{detach:true,spawnRunner:()=>1});
  assert.equal(r.state,'DISPATCHED_DETACHED');
  revokeProjectGrant({worktree:f.repo,storeDir:f.store,reason:'owner changed mind'});
  await assert.rejects(()=>runDetachedDispatch({grantWorktree:f.repo,storeDir:f.store,sessionId:'session-det-111',handoffId:r.handoffId,...f.codex}),/GRANT_REVOKED/);
  assert.equal(existsSync(join(f.repo,'CODEX-ZETA.md')),false,'revoked before start: Codex never ran');
});

test('native dialog: only an explicit click on 승인 approves',t=>{
  const dir=mkdtempGit();t.after(()=>rmSync(dir,{recursive:true,force:true}));
  const g=planGrant({worktree:dir,runs:1,days:1,runMinutes:1});
  const fake=(status,stdout)=>()=>({status,stdout});
  assert.equal(confirmGrantByDialog(g,{platform:'darwin',run:fake(0,'button returned:승인, gave up:false\n')}),'APPROVED');
  assert.equal(confirmGrantByDialog(g,{platform:'darwin',run:fake(1,'')}),'DECLINED','거절 / closed');
  assert.equal(confirmGrantByDialog(g,{platform:'darwin',run:fake(0,'button returned:, gave up:true\n')}),'DECLINED','ignored for 3 minutes');
  assert.equal(confirmGrantByDialog(g,{platform:'win32',run:fake(0,'Yes\r\n')}),'APPROVED');
  assert.equal(confirmGrantByDialog(g,{platform:'win32',run:fake(0,'No\r\n')}),'DECLINED');
  assert.throws(()=>confirmGrantByDialog(g,{platform:'linux'}),/OWNER_DIALOG_UNAVAILABLE/);
  let seen;confirmGrantByDialog(g,{platform:'darwin',run:(cmd,args)=>{seen=args;return {status:1,stdout:''};}});
  assert.ok(seen.at(-1).includes(g.worktree)&&seen.at(-1).includes('최대 1회'),'dialog shows the exact scope');
});

test('grant limits: at most 20 runs, 30 days, 30 minutes per run; git root required',t=>{
  const dir=mkdtempGit();t.after(()=>rmSync(dir,{recursive:true,force:true}));
  assert.throws(()=>planGrant({worktree:dir,runs:21}),/GRANT_LIMIT_INVALID/);
  assert.throws(()=>planGrant({worktree:dir,days:31}),/GRANT_LIMIT_INVALID/);
  assert.throws(()=>planGrant({worktree:dir,runMinutes:31}),/GRANT_LIMIT_INVALID/);
  mkdirSync(join(dir,'sub'));
  assert.throws(()=>planGrant({worktree:join(dir,'sub')}),/GRANT_WORKTREE_MUST_BE_GIT_ROOT/);
  const p=planGrant({worktree:dir,runs:20,days:30,runMinutes:30});
  assert.deepEqual(p.permissions,{workspaceWrite:true,network:false,push:false,deploy:false,credentials:false});
});

function mkdtempGit(){
  const d=mkdtempSync(join(tmpdir(),'rian-grant-dlg-'));
  execFileSync('git',['-C',d,'init','-q']);
  return d;
}

test('status reports whether the five grant hooks are installed in the worktree',async t=>{
  const f=fixture(t);
  await createProjectGrant({worktree:f.repo,storeDir:f.store,runs:1,days:1,runMinutes:1,confirm:f.confirm});
  const before=grantHandoffStatus({worktree:f.repo,storeDir:f.store,probeCodex:false});
  assert.equal(before.hooks.installed,false);assert.equal(before.hooks.missing.length,5);
  assert.ok(before.warnings.some(w=>/HOOKS_NOT_INSTALLED/.test(w)));
  const h=(m)=>[{...(m?{matcher:m}:{}),hooks:[{type:'command',command:'node',args:['/x/automatic-handoff-cli.mjs','hook-grant'],timeout:20}]}];
  mkdirSync(join(f.repo,'.claude'));
  writeFileSync(join(f.repo,'.claude','settings.local.json'),JSON.stringify({hooks:{SessionStart:h(),UserPromptSubmit:h(),PostToolUse:h(),PostToolUseFailure:h(),StopFailure:h('server_error')}}));
  assert.deepEqual(grantHandoffStatus({worktree:f.repo,storeDir:f.store,probeCodex:false}).hooks.missing,['StopFailure'],'StopFailure must match rate_limit');
  writeFileSync(join(f.repo,'.claude','settings.local.json'),JSON.stringify({hooks:{SessionStart:h(),UserPromptSubmit:h(),PostToolUse:h(),PostToolUseFailure:h(),StopFailure:h('rate_limit')}}));
  const after=grantHandoffStatus({worktree:f.repo,storeDir:f.store,probeCodex:false});
  assert.equal(after.hooks.installed,true);assert.deepEqual(after.hooks.files,['.claude/settings.local.json']);
});
