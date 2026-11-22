import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {existsSync,mkdirSync,mkdtempSync,readFileSync,realpathSync,readdirSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {authorizeActivation,automaticHandoffStatus,categorizeHandoffError,handleClaudeHook,readActivationManifest,reconcileAutomaticLease,runDetachedDispatch} from './automatic-handoff.mjs';
import {spawnSync} from 'node:child_process';

function fixture(t,{mode='success',workspaceWrite=true}={}){
  const root=mkdtempSync(join(tmpdir(),'rian-p2-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const repo=join(root,'repo'),store=join(root,'store'),activation=join(repo,'.rian-handoff','activation.json');
  mkdirSync(repo);mkdirSync(join(repo,'.rian-handoff'));
  const git=(...args)=>execFileSync('git',['-C',repo,...args],{encoding:'utf8'}).trim();
  git('init','-q');writeFileSync(join(repo,'README.md'),'base\n');git('add','README.md');
  git('-c','user.name=CI','-c','user.email=ci@example.invalid','commit','-qm','initial');
  writeFileSync(join(repo,'README.md'),'staged\n');git('add','README.md');
  writeFileSync(join(repo,'README.md'),'staged\nunstaged\n');
  writeFileSync(join(repo,'CLAUDE-PARTIAL.md'),'untracked Claude work\n');
  const manifest={schema:'rian-auto-handoff/v1',enabled:true,
    project:{approvedRoot:root,worktree:repo},
    task:{taskId:'task_12345678',goal:'Finish the synthetic feature',pendingSteps:['Review partial work'],testSummary:[]},
    permissions:{workspaceWrite,exclusiveWorktree:true,allowedProviders:['claude','codex']},
    budget:{timeoutMs:mode==='hang'?1200:15_000,checkpointMaxAgeMs:900_000}};
  writeFileSync(activation,JSON.stringify(manifest,null,2));
  const fake=join(root,'fake-codex.mjs');
  writeFileSync(fake,[
    "import {writeFileSync} from 'node:fs';",
    "import {join} from 'node:path';",
    "const args=process.argv.slice(2);",
    "if(args[0]==='--version'){console.log('codex-cli-test 1.0');process.exit(0)}",
    `if(args[0]==='login'&&args[1]==='status'){${mode==='drift-preflight'?"writeFileSync(join(process.cwd(),'README.md'),'changed during preflight\\n');":''}process.exit(${mode==='authfail'?1:0})}`,
    "if(args[0]!=='-a'||args[1]!=='never')process.exit(4);args.splice(0,2);",
    "if(args[0]!=='exec')process.exit(2);",
    "if(!args.includes('sandbox_workspace_write.network_access=false'))process.exit(4);",
    "let p='';for await(const chunk of process.stdin)p+=chunk;",
    "if(!p.includes('Finish the synthetic feature'))process.exit(3);",
    "const wd=args[args.indexOf('--cd')+1];",
    "console.log(JSON.stringify({type:'thread.started',thread_id:'12345678-aaaa-4bbb-8ccc-123456789abc'}));",
    mode==='hang'?"setInterval(()=>{},1000);await new Promise(()=>{});":'',
    mode==='network'?"console.log(JSON.stringify({type:'turn.failed',error:{message:'network connection reset'}}));process.exit(1);":'',
    mode==='usage'?"console.log(JSON.stringify({type:'turn.failed',error:{message:'usage limit reached'}}));process.exit(1);":'',
    mode==='slow'?"await new Promise(r=>setTimeout(r,800));":'',
    "if(args[args.indexOf('--sandbox')+1]==='workspace-write')writeFileSync(join(wd,'CODEX-RESULT.md'),'Codex continued\\n');",
    "console.log(JSON.stringify({type:'item.completed',item:{type:'command_execution',command:'node --test synthetic.test.mjs',exit_code:0}}));",
    "console.log(JSON.stringify({type:'turn.completed'}));"
  ].filter(Boolean).join('\n')+'\n');
  authorizeActivation({manifestPath:activation,storeDir:store,ownerApproved:true});
  const event=(hook_event_name,error,session_id='session-test-123')=>({hook_event_name,error,session_id,cwd:repo});
  const run=e=>handleClaudeHook({event:e,manifestPath:activation,storeDir:store,codexCommand:process.execPath,codexPrefixArgs:[fake]});
  return {root,repo,store,activation,manifest,git,event,run};
}

test('incremental official hooks preserve staged, unstaged and untracked work through automatic dispatch',async t=>{
  const f=fixture(t);
  assert.deepEqual(await f.run(f.event('SessionStart')),{state:'CHECKPOINTED',sequence:1});
  assert.deepEqual(await f.run(f.event('PostToolUse')),{state:'CHECKPOINTED',sequence:2});
  const result=await f.run(f.event('StopFailure','rate_limit'));
  assert.equal(result.state,'COMPLETED');
  assert.match(readFileSync(join(f.repo,'README.md'),'utf8'),/unstaged/);
  assert.match(f.git('diff','--cached','README.md'),/staged/);
  assert.match(readFileSync(join(f.repo,'CLAUDE-PARTIAL.md'),'utf8'),/untracked/);
  assert.match(readFileSync(join(f.repo,'CODEX-RESULT.md'),'utf8'),/Codex continued/);
  const receipt=JSON.parse(readFileSync(join(f.store,'receipts',result.handoffId+'.json')));
  assert.equal(receipt.state,'COMPLETED');
  assert.equal(receipt.threadId,result.threadId);
  assert.equal(receipt.testChecks.passed,1);
  assert.equal(receipt.commandChecks.passed,1);
  assert.equal(receipt.changedAfter.some(x=>x.path==='CODEX-RESULT.md'),true);
  await assert.rejects(()=>f.run(f.event('StopFailure','rate_limit')),/AUTOMATIC_DISPATCH_ALREADY_ATTEMPTED/);
  await f.run(f.event('SessionStart',undefined,'new-session-123'));
  await assert.rejects(()=>f.run(f.event('StopFailure','rate_limit','new-session-123')),/PROJECT_TASK_ALREADY_ATTEMPTED/);
});

test('only official rate limit with same fresh checkpoint and unchanged content can dispatch',async t=>{
  const f=fixture(t);
  assert.equal((await f.run(f.event('StopFailure','server_error'))).state,'IGNORED');
  await assert.rejects(()=>f.run(f.event('StopFailure','rate_limit')),/CHECKPOINT_MISSING/);
  await f.run(f.event('UserPromptSubmit'));
  assert.equal((await f.run(f.event('StopFailure','billing_error'))).state,'IGNORED');
  await assert.rejects(()=>f.run(f.event('StopFailure','rate_limit','different-session')),/CHECKPOINT_MISSING/);
  writeFileSync(join(f.repo,'CLAUDE-PARTIAL.md'),'same path with changed contents\n');
  await assert.rejects(()=>f.run(f.event('StopFailure','rate_limit')),/WORKTREE_CHANGED_AFTER_CHECKPOINT/);
  assert.equal(existsSync(join(f.repo,'CODEX-RESULT.md')),false);
});

test('manifest edit invalidates owner seal and read-only grant stays read-only',async t=>{
  const f=fixture(t,{workspaceWrite:false});
  await f.run(f.event('SessionStart'));
  const result=await f.run(f.event('StopFailure','rate_limit'));
  assert.equal(result.state,'COMPLETED');
  assert.equal(existsSync(join(f.repo,'CODEX-RESULT.md')),false);
  f.manifest.permissions.workspaceWrite=true;
  writeFileSync(f.activation,JSON.stringify(f.manifest));
  await assert.rejects(()=>f.run(f.event('SessionStart')),/ACTIVATION_SEAL_MISMATCH/);
  assert.equal(readActivationManifest(f.activation).manifest.permissions.workspaceWrite,true);
});

test('concurrent trigger is single-dispatch even before the first process finishes',async t=>{
  const f=fixture(t,{mode:'slow'});
  await f.run(f.event('PostToolUse'));
  const first=f.run(f.event('StopFailure','rate_limit'));
  await assert.rejects(()=>f.run(f.event('StopFailure','rate_limit')),/AUTOMATIC_DISPATCH_ALREADY_ATTEMPTED/);
  assert.equal((await first).state,'COMPLETED');
  assert.equal(readdirSync(join(f.store,'receipts')).length,1);
});

test('distinct Claude sessions cannot dispatch the same approved task',async t=>{
  const f=fixture(t,{mode:'slow'});
  await f.run(f.event('SessionStart',undefined,'session-one'));
  await f.run(f.event('SessionStart',undefined,'session-two'));
  const first=f.run(f.event('StopFailure','rate_limit','session-one'));
  await assert.rejects(()=>f.run(f.event('StopFailure','rate_limit','session-two')),/PROJECT_TASK_ALREADY_ATTEMPTED/);
  assert.equal((await first).state,'COMPLETED');
});

test('auth failure, usage limit and network uncertainty stop without duplicate replay',async t=>{
  for(const [mode,expected] of [['authfail','CODEX_NOT_AUTHENTICATED'],['usage','FAILED'],['network','UNKNOWN_DO_NOT_RETRY']]){
    const f=fixture(t,{mode});
    await f.run(f.event('SessionStart'));
    if(mode==='authfail')await assert.rejects(()=>f.run(f.event('StopFailure','rate_limit')),new RegExp(expected));
    else{
      const result=await f.run(f.event('StopFailure','rate_limit'));
      assert.equal(result.state,expected);
      const receipt=JSON.parse(readFileSync(join(f.store,'receipts',result.handoffId+'.json')));
      assert.equal(receipt.state,expected);
      if(mode==='network')assert.equal(result.lockRetained,true);
      if(mode==='usage')assert.equal(receipt.failureKind,'USAGE_LIMIT');
    }
    await assert.rejects(()=>f.run(f.event('StopFailure','rate_limit')),/AUTOMATIC_DISPATCH_ALREADY_ATTEMPTED/);
  }
});

test('timeout retains lease; audited recovery releases it without replay',async t=>{
  const f=fixture(t,{mode:'hang'});
  await f.run(f.event('SessionStart'));
  const result=await f.run(f.event('StopFailure','rate_limit'));
  assert.equal(result.state,'UNKNOWN_DO_NOT_RETRY');
  assert.equal(result.lockRetained,true);
  assert.throws(()=>reconcileAutomaticLease({manifestPath:f.activation,storeDir:f.store,handoffId:result.handoffId,
    reason:'Verified process has stopped'}),/OWNER_VERIFICATION_REQUIRED/);
  const recovery=reconcileAutomaticLease({manifestPath:f.activation,storeDir:f.store,handoffId:result.handoffId,
    ownerVerifiedNoWriter:true,reason:'Verified process has stopped'});
  assert.equal(recovery.state,'RECONCILED_NO_RETRY');
  assert.equal(existsSync(recovery.auditPath),true);
  await assert.rejects(()=>f.run(f.event('StopFailure','rate_limit')),/AUTOMATIC_DISPATCH_ALREADY_ATTEMPTED/);
});

test('dispatch crash leaves a review marker and cannot replay the session',async t=>{
  const f=fixture(t);
  await f.run(f.event('SessionStart'));
  const receiver={name:'synthetic-crash',async dispatch(){throw Error('SIMULATED_DISPATCH_CRASH');}};
  await assert.rejects(()=>handleClaudeHook({event:f.event('StopFailure','rate_limit'),manifestPath:f.activation,
    storeDir:f.store,receiver}),/SIMULATED_DISPATCH_CRASH/);
  const marker=JSON.parse(readFileSync(join(f.store,'automatic-dispatch',readdirSync(join(f.store,'automatic-dispatch'))[0])));
  assert.equal(marker.state,'BLOCKED_REVIEW');
  await assert.rejects(()=>f.run(f.event('StopFailure','rate_limit')),/AUTOMATIC_DISPATCH_ALREADY_ATTEMPTED/);
});

test('owner scope and sensitive task notes are validated before activation',t=>{
  const f=fixture(t);
  f.manifest.project.approvedRoot=join(f.root,'other');
  writeFileSync(f.activation,JSON.stringify(f.manifest));
  assert.throws(()=>readActivationManifest(f.activation));
  f.manifest.project.approvedRoot=f.root;
  f.manifest.task.goal='Read ~/.codex/auth.json';
  writeFileSync(f.activation,JSON.stringify(f.manifest));
  assert.throws(()=>readActivationManifest(f.activation),/SENSITIVE_HANDOFF_NOTES_DENIED/);
});

test('orphaned pre-receipt lease needs owner audit and cannot be silently reused',t=>{
  const f=fixture(t),handoffId='12345678-aaaa-4bbb-8ccc-123456789abc';
  const leases=join(f.store,'leases');mkdirSync(leases);
  const canonical=realpathSync(f.repo),lock=join(leases,createHash('sha256').update(canonical).digest('hex')+'.lock');
  writeFileSync(lock,JSON.stringify({handoffId,attemptId:'87654321-aaaa-4bbb-8ccc-123456789abc',worktree:canonical}),{mode:0o600});
  assert.throws(()=>reconcileAutomaticLease({manifestPath:f.activation,storeDir:f.store,handoffId,
    ownerVerifiedNoWriter:true,reason:'short'}),/INVALID_RECOVERY_REQUEST/);
  const result=reconcileAutomaticLease({manifestPath:f.activation,storeDir:f.store,handoffId,
    ownerVerifiedNoWriter:true,reason:'Inspected orphaned lease and stopped writers'});
  assert.equal(result.state,'RECONCILED_NO_RETRY');
  assert.equal(existsSync(lock),false);
  assert.equal(JSON.parse(readFileSync(join(f.store,'receipts',handoffId+'.json'))).state,'RECONCILED_NO_RETRY');
});

test('worktree content drift during Codex preflight blocks launch',async t=>{
  const f=fixture(t,{mode:'drift-preflight'});
  await f.run(f.event('SessionStart'));
  await assert.rejects(()=>f.run(f.event('StopFailure','rate_limit')),/WORKTREE_CHANGED_BEFORE_DISPATCH/);
  assert.equal(existsSync(join(f.repo,'CODEX-RESULT.md')),false);
  assert.equal(readdirSync(join(f.store,'receipts')).length,0);
});

test('status explains why automatic handoff would not run: approval, checkpoint, execution',async t=>{
  const f=fixture(t);
  const fakeCodex={codexCommand:process.execPath,codexPrefixArgs:[join(f.root,'fake-codex.mjs')]};
  const unapproved=automaticHandoffStatus({manifestPath:f.activation,storeDir:join(f.root,'other-store'),...fakeCodex});
  assert.equal(unapproved.ready,false);
  assert.equal(unapproved.approval.state,'NOT_APPROVED');
  assert.deepEqual(unapproved.blockers,[{code:'ACTIVATION_NOT_APPROVED',category:'APPROVAL'}]);
  await assert.rejects(()=>handleClaudeHook({event:f.event('SessionStart'),manifestPath:f.activation,storeDir:join(f.root,'other-store')}),/ACTIVATION_NOT_APPROVED/);
  const fresh=automaticHandoffStatus({manifestPath:f.activation,storeDir:f.store,...fakeCodex});
  assert.equal(fresh.ready,true);
  assert.equal(fresh.codex.loggedIn,true);
  assert.match(fresh.warnings[0],/NO_CHECKPOINT_YET/);
  await f.run(f.event('PostToolUse'));
  const cp=automaticHandoffStatus({manifestPath:f.activation,storeDir:f.store,...fakeCodex});
  assert.equal(cp.lastCheckpoint.fresh,true);assert.equal(cp.lastCheckpoint.sequence,1);
  writeFileSync(join(f.repo,'CLAUDE-PARTIAL.md'),'changed after checkpoint\n');
  await assert.rejects(()=>f.run(f.event('StopFailure','rate_limit')),/WORKTREE_CHANGED_AFTER_CHECKPOINT/);
  const blocked=automaticHandoffStatus({manifestPath:f.activation,storeDir:f.store,...fakeCodex});
  assert.equal(blocked.lastTrigger.state,'BLOCKED');
  assert.equal(blocked.lastTrigger.error,'WORKTREE_CHANGED_AFTER_CHECKPOINT');
  assert.equal(blocked.lastTrigger.category,'CHECKPOINT');
  await f.run(f.event('PostToolUse'));
  assert.equal((await f.run(f.event('StopFailure','rate_limit'))).state,'COMPLETED');
  assert.equal((await f.run(f.event('StopFailure','billing_error'))).state,'IGNORED');
  const done=automaticHandoffStatus({manifestPath:f.activation,storeDir:f.store,...fakeCodex});
  assert.equal(done.lastTrigger.state,'IGNORED');
  assert.equal(done.lastDispatch.state,'COMPLETED','an ignored stop does not hide the dispatch outcome');assert.ok(done.lastDispatch.handoffId);
  assert.ok(done.warnings.some(w=>/OWNER_ATTENTION_REQUIRED/.test(w)));
  assert.deepEqual(done.blockers,[{code:'PROJECT_TASK_ALREADY_ATTEMPTED',category:'EXECUTION'}]);
  f.manifest.budget.timeoutMs=60_000;writeFileSync(f.activation,JSON.stringify(f.manifest));
  assert.equal(automaticHandoffStatus({manifestPath:f.activation,storeDir:f.store,probeCodex:false}).approval.state,'CHANGED_REAPPROVAL_REQUIRED');
  assert.equal(categorizeHandoffError('CODEX_NOT_AUTHENTICATED'),'EXECUTION');
  assert.equal(categorizeHandoffError('CHECKPOINT_MISSING'),'CHECKPOINT');
});

test('CLI: status exit code and categorized hook errors without a TTY',async t=>{
  const f=fixture(t);
  const cli=join(import.meta.dirname,'automatic-handoff-cli.mjs');
  const st=spawnSync(process.execPath,[cli,'status','--manifest',f.activation,'--store',join(f.root,'other-store')],{encoding:'utf8'});
  assert.equal(st.status,2);
  assert.equal(JSON.parse(st.stdout).approval.state,'NOT_APPROVED');
  const hook=spawnSync(process.execPath,[cli,'hook','--manifest',f.activation,'--store',f.store],
    {input:JSON.stringify(f.event('StopFailure','rate_limit')),encoding:'utf8'});
  assert.equal(hook.status,1);
  assert.deepEqual((({state,error,category})=>({state,error,category}))(JSON.parse(hook.stderr)),{state:'BLOCKED',error:'CHECKPOINT_MISSING',category:'CHECKPOINT'});
  const approve=spawnSync(process.execPath,[cli,'approve','--manifest',f.activation,'--store',f.store],{input:'APPROVE x\n',encoding:'utf8'});
  assert.equal(JSON.parse(approve.stderr).error,'INTERACTIVE_OWNER_TERMINAL_REQUIRED','approval cannot be scripted');
});

test('detached dispatch: hook returns at once, the runner executes the claim exactly once',async t=>{
  const f=fixture(t);
  const fake={codexCommand:process.execPath,codexPrefixArgs:[join(f.root,'fake-codex.mjs')]};
  await f.run(f.event('PostToolUse'));
  let spawned=null;
  const r=await handleClaudeHook({event:f.event('StopFailure','rate_limit'),manifestPath:f.activation,storeDir:f.store,detach:true,
    spawnRunner:args=>{spawned=args;return 424242;}});
  assert.equal(r.state,'DISPATCHED_DETACHED');assert.equal(r.runnerPid,424242);
  assert.equal(existsSync(join(f.repo,'CODEX-RESULT.md')),false,'nothing ran inside the hook');
  assert.deepEqual(spawned.slice(0,1),['dispatch-run']);
  assert.equal(spawned[spawned.indexOf('--handoff-id')+1],r.handoffId);
  const pending=automaticHandoffStatus({manifestPath:f.activation,storeDir:f.store,probeCodex:false});
  assert.equal(pending.lastDispatch.markerState,'DETACHED');
  assert.ok(pending.warnings.some(w=>/DETACHED_RUNNER_EXITED_WITHOUT_RESULT/.test(w)),'a dead runner pid is reported');
  const done=await runDetachedDispatch({manifestPath:f.activation,storeDir:f.store,sessionId:'session-test-123',handoffId:r.handoffId,...fake});
  assert.equal(done.state,'COMPLETED');
  assert.equal(readFileSync(join(f.repo,'CODEX-RESULT.md'),'utf8'),'Codex continued\n');
  await assert.rejects(()=>runDetachedDispatch({manifestPath:f.activation,storeDir:f.store,sessionId:'session-test-123',handoffId:r.handoffId,...fake}),/DISPATCH_NOT_PENDING/);
  const after=automaticHandoffStatus({manifestPath:f.activation,storeDir:f.store,probeCodex:false});
  assert.equal(after.lastDispatch.state,'COMPLETED');assert.equal(after.lastDispatch.markerState,'COMPLETED');
  assert.equal(after.lease,null);
});

test('detached runner re-verifies the worktree and the owner seal before Codex starts',async t=>{
  const f=fixture(t);
  const fake={codexCommand:process.execPath,codexPrefixArgs:[join(f.root,'fake-codex.mjs')]};
  await f.run(f.event('PostToolUse'));
  const r=await handleClaudeHook({event:f.event('StopFailure','rate_limit'),manifestPath:f.activation,storeDir:f.store,detach:true,spawnRunner:()=>1});
  writeFileSync(join(f.repo,'CLAUDE-PARTIAL.md'),'Claude kept writing after the limit\n');
  await assert.rejects(()=>runDetachedDispatch({manifestPath:f.activation,storeDir:f.store,sessionId:'session-test-123',handoffId:r.handoffId,...fake}),/WORKTREE_CHANGED_BEFORE_DISPATCH/);
  assert.equal(existsSync(join(f.repo,'CODEX-RESULT.md')),false);
  const s=automaticHandoffStatus({manifestPath:f.activation,storeDir:f.store,probeCodex:false});
  assert.equal(s.lastDispatch.state,'BLOCKED');assert.equal(s.lastDispatch.category,'CHECKPOINT');
  await assert.rejects(()=>runDetachedDispatch({manifestPath:f.activation,storeDir:f.store,sessionId:'session-test-123',handoffId:r.handoffId,...fake}),/DISPATCH_NOT_PENDING/,'no second attempt');
});

test('budget: up to 30 minutes for the detached Codex run, never more',async t=>{
  const f=fixture(t);
  f.manifest.budget.timeoutMs=1_800_000;writeFileSync(f.activation,JSON.stringify(f.manifest));
  assert.equal(readActivationManifest(f.activation).manifest.budget.timeoutMs,1_800_000);
  f.manifest.budget.timeoutMs=1_800_001;writeFileSync(f.activation,JSON.stringify(f.manifest));
  assert.throws(()=>readActivationManifest(f.activation),/INVALID_BUDGET/);
});
