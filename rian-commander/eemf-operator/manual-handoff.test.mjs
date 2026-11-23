import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,existsSync,rmSync,chmodSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync,spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {prepareManualHandoff,readManualCheckpoint,executeManualHandoff} from './manual-handoff.mjs';

function fixture(t){
  const root=mkdtempSync(join(tmpdir(),'rian-p1-e2e-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const repo=join(root,'repo'),store=join(root,'store');mkdirSync(repo);
  const git=(...args)=>execFileSync('git',['-C',repo,...args],{stdio:'ignore'});
  git('init','-q');writeFileSync(join(repo,'README.md'),'Before Claude task\n');
  git('add','.');git('-c','user.name=CI','-c','user.email=ci@example.invalid','commit','-qm','initial');
  writeFileSync(join(repo,'CLAUDE-PARTIAL.md'),'Claude wrote this partial step and stopped.\n');
  const fake=join(root,'fake-codex.mjs');
  writeFileSync(fake,[
    "import {writeFileSync} from 'node:fs';",
    "import {join} from 'node:path';",
    "const args=process.argv.slice(2);",
    "if(args[0]==='--version'){console.log('codex-cli-test 1.0');process.exit(0)}",
    "if(args[0]==='login'&&args[1]==='status'){process.exit(process.env.MOCK_LOGIN_FAIL==='1'?1:0)}",
    "if(args[0]==='exec'){",
    "  let p='';for await(const chunk of process.stdin)p+=chunk;",
    "  const wd=args[args.indexOf('--cd')+1];",
    "  if(!p.includes('Claude Code')||!p.includes('Finish this synthetic feature'))process.exit(5);",
    "  if(p.includes('Hang to test timeout')){setInterval(()=>{},1000);await new Promise(()=>{});}",
    "  if(args[args.indexOf('--sandbox')+1]==='workspace-write')writeFileSync(join(wd,'CODEX-RESULT.md'),'Resumed from Claude checkpoint.\\n');",
    "  console.log(JSON.stringify({type:'thread.started',thread_id:'12345678-aaaa-4bbb-8ccc-123456789abc'}));",
    "  console.log(JSON.stringify({type:'turn.completed'}));",
    "  process.exit(0);",
    "}",
    "process.exit(2);"
  ].join('\n')+'\n');
  const prep=({taskId='task_12345678',workspaceWrite=true,goal='Finish this synthetic feature',...rest}={})=>prepareManualHandoff({approvedRoot:root,worktree:repo,taskId,goal,workspaceWrite,storeDir:store,
    pendingSteps:['Verify the Claude partial file', 'Finish Codex implementation'],testSummary:['previous baseline PASS'],...rest});
  const execute=(cp,opts={})=>executeManualHandoff({checkpointPath:cp.path,approvedRoot:root,storeDir:store,
    ownerApproved:true,claudeStopped:true,codexCommand:process.execPath,codexPrefixArgs:[fake],timeoutMs:15_000,...opts});
  return {root,repo,store,fake,prep,execute};
}

test('P1 local E2E: Claude dirty worktree is preserved and mock Codex continues',async t=>{
  const f=fixture(t),cp=f.prep();
  assert.equal(cp.handoff.repository.dirty,true);
  assert.equal(readManualCheckpoint({checkpointPath:cp.path,storeDir:f.store}).handoffId,cp.handoff.handoffId);
  assert.equal(existsSync(join(f.repo,'CODEX-RESULT.md')),false);
  const result=await f.execute(cp);
  assert.equal(result.state,'COMPLETED');
  assert.equal(result.events,2);
  assert.equal(result.threadId,'12345678-aaaa-4bbb-8ccc-123456789abc');
  assert.equal(result.lockRetained,false);
  assert.match(readFileSync(join(f.repo,'CLAUDE-PARTIAL.md'),'utf8'),/Claude wrote/);
  assert.match(readFileSync(join(f.repo,'CODEX-RESULT.md'),'utf8'),/Resumed/);
  assert.throws(()=>readManualCheckpoint({checkpointPath:join(f.root,'other.json'),storeDir:f.store}),/CHECKPOINT_OUTSIDE_STORE/);
  await assert.rejects(()=>f.execute(cp),/HANDOFF_ALREADY_ATTEMPTED/);
});

test('Manual owner consent and stopped-Claude acknowledgment are mandatory',async t=>{
  const f=fixture(t),cp=f.prep();
  await assert.rejects(()=>f.execute(cp,{ownerApproved:false}),/OWNER_AND_QUIESCENCE_CONFIRMATION_REQUIRED/);
  await assert.rejects(()=>f.execute(cp,{claudeStopped:false}),/OWNER_AND_QUIESCENCE_CONFIRMATION_REQUIRED/);
  assert.equal(existsSync(join(f.repo,'CODEX-RESULT.md')),false);
});

test('Changed Git HEAD or untracked paths after checkpoint blocks handoff',async t=>{
  const f=fixture(t),cp=f.prep();
  writeFileSync(join(f.repo,'UNEXPECTED.md'),'new untracked file\n');
  await assert.rejects(()=>f.execute(cp),/GIT_WORKTREE_CHANGED_AFTER_CHECKPOINT/);
  assert.equal(existsSync(join(f.repo,'CODEX-RESULT.md')),false);
});

test('Private notes and non-private checkpoint files are rejected',async t=>{
  const f=fixture(t);
  assert.throws(()=>f.prep({goal:'Use Bearer sk-proj-THISISACREDENTIALVALUE12345'}),/SENSITIVE_HANDOFF_NOTES_DENIED/);
  const cp=f.prep();
  if(process.platform!=='win32'){
    chmodSync(cp.path,0o644);
    assert.throws(()=>readManualCheckpoint({checkpointPath:cp.path,storeDir:f.store}),/CHECKPOINT_PERMISSIONS/);
  }
});

test('One active worktree lease prevents concurrent provider execution',async t=>{
  const f=fixture(t),cp=f.prep();
  const leases=join(f.store,'leases');mkdirSync(leases);
  const hash=createHash('sha256').update(cp.handoff.repository.worktree).digest('hex');
  writeFileSync(join(leases,hash+'.lock'),'{"attemptId":"other"}');
  await assert.rejects(()=>f.execute(cp),/WORKTREE_ALREADY_LEASED/);
  assert.equal(existsSync(join(f.repo,'CODEX-RESULT.md')),false);
});

test('Read-only permission is not escalated by local P1 runner',async t=>{
  const f=fixture(t),cp=f.prep({workspaceWrite:false});
  const result=await f.execute(cp);
  assert.equal(result.state,'COMPLETED');
  assert.equal(existsSync(join(f.repo,'CODEX-RESULT.md')),false);
});

test('Timeout retains lease and prevents automatic retry',async t=>{
  const f=fixture(t),cp=f.prep({goal:'Finish this synthetic feature — Hang to test timeout'});
  const result=await f.execute(cp,{timeoutMs:1200});
  assert.equal(result.state,'UNKNOWN_DO_NOT_RETRY');
  assert.equal(result.lockRetained,true);
  await assert.rejects(()=>f.execute(cp),/HANDOFF_ALREADY_ATTEMPTED/);
});

test('No actual Codex CLI is called when owner uses preview-only command',t=>{
  const f=fixture(t),cp=f.prep();
  const cli=join(import.meta.dirname,'manual-handoff-cli.mjs');
  const r=spawnSync(process.execPath,[cli,'preview','--checkpoint',cp.path,'--store',f.store],{encoding:'utf8'});
  assert.equal(r.status,0,r.stderr);
  assert.equal(JSON.parse(r.stdout).handoffId,cp.handoff.handoffId);
  assert.equal(existsSync(join(f.repo,'CODEX-RESULT.md')),false);
});
