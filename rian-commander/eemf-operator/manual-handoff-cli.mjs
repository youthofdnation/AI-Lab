#!/usr/bin/env node
/** Owner-operated local CLI. No background tasks or automatic switching. */
import {resolve,join} from 'node:path';
import {homedir} from 'node:os';
import {createInterface} from 'node:readline/promises';
import {stdin as input,stdout as output} from 'node:process';
import {prepareManualHandoff,readManualCheckpoint,executeManualHandoff} from './manual-handoff.mjs';

function parse(args){
  const result={next:[],tests:[]};
  for(let i=0;i<args.length;i++){
    const key=args[i];
    if(key==='--workspace-write'||key==='--claude-stopped'){result[key.slice(2).replaceAll('-','_')]=true;continue;}
    const allowed=['--root','--worktree','--task-id','--goal','--next','--tests','--store','--checkpoint'];
    if(!allowed.includes(key)||i===args.length-1)throw Error('INVALID_OPTION');
    const val=args[++i];
    if(key==='--next'||key==='--tests')result[key.slice(2)].push(val);
    else result[key.slice(2).replaceAll('-','_')]=val;
  }
  return result;
}
const storeDefault=join(homedir(),'.rian-commander','handoffs');
const usage=()=>[
  'RIAN Agent Handoff P1 (manual; local only)',
  'Prepare (does not start Codex):',
  'node manual-handoff-cli.mjs prepare --root /approved --worktree /approved/repo --task-id TASK_12345678 --goal "..." [--next "..."] [--tests "..."] [--workspace-write]',
  'Execute (requires human terminal confirmation and stopped Claude session):',
  'node manual-handoff-cli.mjs run --root /approved --checkpoint /absolute/path/to/checkpoint.json --claude-stopped [--store /private/path]',
  'Review a checkpoint without executing:',
  'node manual-handoff-cli.mjs preview --checkpoint /absolute/path/to/checkpoint.json [--store /private/path]',
  'No deploy, push, source deletion, mail, model-provider auth export or cross-device switching is enabled.'
].join('\n')+'\n';
async function main(){
  const [action,...argv]=process.argv.slice(2);
  if(!['prepare','preview','run'].includes(action)){output.write(usage());process.exitCode=1;return;}
  const opts=parse(argv),storeDir=opts.store?resolve(opts.store):storeDefault;
  if(action==='prepare'){
    if(!opts.root||!opts.worktree||!opts.task_id||!opts.goal)throw Error('MISSING_PREPARE_ARGS');
    const cp=prepareManualHandoff({approvedRoot:resolve(opts.root),worktree:resolve(opts.worktree),taskId:opts.task_id,
      goal:opts.goal,pendingSteps:opts.next,testSummary:opts.tests,workspaceWrite:!!opts.workspace_write,storeDir});
    output.write(JSON.stringify({ok:true,action,checkpoint:cp.path,branch:cp.handoff.repository.branch,head:cp.handoff.repository.head,changedPaths:cp.handoff.repository.changed.length,workspaceWrite:cp.handoff.authorization.workspaceWrite},null,2)+'\n');
    return;
  }
  if(!opts.checkpoint)throw Error('CHECKPOINT_REQUIRED');
  const handoff=readManualCheckpoint({checkpointPath:resolve(opts.checkpoint),storeDir});
  const info={ok:true,action:'preview',handoffId:handoff.handoffId,taskId:handoff.taskId,
    worktree:handoff.repository.worktree,head:handoff.repository.head,branch:handoff.repository.branch,
    workspaceWrite:handoff.authorization.workspaceWrite,goal:handoff.task.goal,
    changedPaths:handoff.repository.changed.map(x=>x.path),pendingSteps:handoff.task.pendingSteps};
  output.write(JSON.stringify(info,null,2)+'\n');
  if(action==='preview')return;
  if(!opts.root||!opts.claude_stopped)throw Error('REQUIRES_ROOT_AND_STOPPED_CLAUDE_CONFIRMATION');
  if(!input.isTTY||!output.isTTY)throw Error('INTERACTIVE_OWNER_TERMINAL_REQUIRED');
  const phrase='RUN '+handoff.handoffId.slice(0,8);
  const rl=createInterface({input,output});
  let answer;
  try{answer=await rl.question('Confirm Claude is stopped and Codex may use the displayed workspace. Type '+phrase+': ');}finally{rl.close();}
  if(answer.trim()!==phrase)throw Error('OWNER_APPROVAL_NOT_GIVEN');
  const result=await executeManualHandoff({checkpointPath:resolve(opts.checkpoint),approvedRoot:resolve(opts.root),storeDir,
    ownerApproved:true,claudeStopped:true});
  output.write(JSON.stringify({handoffId:result.handoffId,state:result.state,events:result.events,threadId:result.threadId,
    exitCode:result.exitCode,gitAfter:result.gitAfter,lockRetained:result.lockRetained},null,2)+'\n');
  if(result.state!=='COMPLETED')process.exitCode=2;
}
main().catch(e=>{console.error(JSON.stringify({ok:false,error:e?.message||'HANDOFF_ERROR'}));process.exitCode=1;});
