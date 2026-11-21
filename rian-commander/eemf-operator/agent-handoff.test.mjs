import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,statSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {classifyClaudeStop,inspectWorktree,buildHandoff,saveLocalHandoff,planCodexHandoff} from './agent-handoff.mjs';

const scope={allowedProviders:['claude','codex'],workspaceWrite:true};
const failure={hook_event_name:'StopFailure',error:'rate_limit'};
function fixture(t){
  const root=mkdtempSync(join(tmpdir(),'rian-handoff-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const repo=join(root,'project');mkdirSync(repo);
  const git=(...a)=>execFileSync('git',['-C',repo,...a]);
  git('init','-q');writeFileSync(join(repo,'README.md'),'initial\n');
  git('add','.');git('-c','user.name=RIAN Test','-c','user.email=test@example.invalid','commit','-qm','initial');
  return {root,repo};
}

test('Only StopFailure rate_limit causes an automatic provider switch',()=>{
  assert.equal(classifyClaudeStop(failure),'CLAUDE_RATE_LIMIT');
  assert.equal(classifyClaudeStop({hook_event_name:'StopFailure',error:'billing_error'}),'OWNER_ATTENTION_REQUIRED');
  assert.equal(classifyClaudeStop({hook_event_name:'StopFailure',error:'server_error'}),'NO_TRIGGER');
  assert.equal(classifyClaudeStop({hook_event_name:'Stop',error:'rate_limit'}),'NO_TRIGGER');
  assert.equal(classifyClaudeStop({error:'rate_limit'}),'NO_TRIGGER');
});

test('Git snapshot is read-only, bounded and excludes sensitive paths',t=>{
  const {root,repo}=fixture(t);
  writeFileSync(join(repo,'README.md'),'changed\n');
  writeFileSync(join(repo,'.env'),'SHOULD_NOT_LEAK=1\n');
  const state=inspectWorktree({approvedRoot:root,worktree:repo});
  assert.equal(state.dirty,true);
  assert.equal(state.changed.some(x=>x.path==='README.md'),true);
  assert.equal(state.changed.some(x=>x.path==='.env'),false);
  assert.equal(state.omittedSensitivePaths,1);
  assert.throws(()=>inspectWorktree({approvedRoot:repo,worktree:root}),/WORKTREE_OUTSIDE_OWNER_SCOPE|WORKTREE_MUST_BE_GIT_ROOT/);
});

test('Active job, unknown state, foreign provider and unapproved switching fail closed',t=>{
  const {root,repo}=fixture(t);
  const state=inspectWorktree({approvedRoot:root,worktree:repo});
  const base={taskId:'dev_123456789',goal:'Finish unit tests',repo:state,event:failure,ownerScope:scope};
  assert.throws(()=>buildHandoff({...base,activeJobs:[{state:'UNKNOWN_DO_NOT_RETRY'}]}),/ACTIVE_JOB_CANNOT_HANDOFF/);
  assert.throws(()=>buildHandoff({...base,ownerScope:{allowedProviders:['claude'],workspaceWrite:true}}),/PROVIDER_SCOPE_NOT_APPROVED/);
  assert.throws(()=>buildHandoff({...base,event:{hook_event_name:'StopFailure',error:'authentication_failed'}}),/UNSUPPORTED_HANDOFF_TRIGGER/);
  const handoff=buildHandoff({...base,pendingSteps:['Run unit tests'],testSummary:['node tests PASS']});
  assert.equal(handoff.trigger,'CLAUDE_RATE_LIMIT');
  assert.equal(handoff.state,'READY_FOR_CODEX');
  assert.throws(()=>planCodexHandoff(handoff),/OWNER_HANDOFF_APPROVAL_REQUIRED/);
  const plan=planCodexHandoff(handoff,{ownerApproved:true});
  assert.deepEqual(plan.args,['exec','--json','--sandbox','workspace-write','--cd',repo,'-']);
  assert.equal(plan.command,'codex');
  assert.match(plan.stdin,/Run unit tests/);
  assert.equal(plan.stdin.includes('SHOULD_NOT_LEAK'),false);
  const file=saveLocalHandoff(handoff,{directory:join(root,'handoffs')});
  assert.equal(JSON.parse(readFileSync(file,'utf8')).handoffId,handoff.handoffId);
  if(process.platform!=='win32')assert.equal(statSync(file).mode&0o777,0o600);
  assert.throws(()=>saveLocalHandoff(handoff,{directory:join(root,'handoffs')}),/HANDOFF_ALREADY_EXISTS/);
});

test('Read-only owner scope cannot escalate to workspace-write',t=>{
  const {root,repo}=fixture(t);
  const handoff=buildHandoff({
    taskId:'dev_123456790',goal:'Review code',repo:inspectWorktree({approvedRoot:root,worktree:repo}),
    event:'manual',ownerScope:{allowedProviders:['claude','codex'],workspaceWrite:false}
  });
  assert.equal(planCodexHandoff(handoff,{ownerApproved:true}).args[3],'read-only');
});
