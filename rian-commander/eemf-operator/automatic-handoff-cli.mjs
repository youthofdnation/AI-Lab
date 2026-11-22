#!/usr/bin/env node
/** Owner-operated approval/recovery and Claude command-hook entry point. */
import {stdin,stdout} from 'node:process';
import {createInterface} from 'node:readline/promises';
import {resolve} from 'node:path';
import {authorizeActivation,automaticHandoffStatus,categorizeHandoffError,handleClaudeHook,readActivationManifest,reconcileAutomaticLease,runDetachedDispatch} from './automatic-handoff.mjs';

function args(argv){
  const out={};
  for(let i=0;i<argv.length;i+=2){
    if(!['--manifest','--store','--handoff-id','--reason','--session'].includes(argv[i])||!argv[i+1]||out[argv[i]])throw Error('INVALID_OPTION');
    out[argv[i].slice(2).replaceAll('-','_')]=argv[i+1];
  }
  return out;
}
async function confirm(phrase){
  if(!stdin.isTTY||!stdout.isTTY)throw Error('INTERACTIVE_OWNER_TERMINAL_REQUIRED');
  const rl=createInterface({input:stdin,output:stdout});
  try{if((await rl.question('Type '+phrase+': ')).trim()!==phrase)throw Error('OWNER_APPROVAL_NOT_GIVEN');}
  finally{rl.close();}
}
async function hookInput(){
  let data='';
  for await(const chunk of stdin){data+=chunk;if(data.length>64_000)throw Error('HOOK_INPUT_TOO_LARGE');}
  return JSON.parse(data);
}
async function main(){
  const [action,...rest]=process.argv.slice(2),o=args(rest);
  if(!['approve','hook','recover','status','dispatch-run'].includes(action)||!o.manifest)throw Error('USAGE: approve|hook|recover|status --manifest ABSOLUTE_PATH [--store PRIVATE_PATH]');
  const manifestPath=resolve(o.manifest),storeDir=o.store?resolve(o.store):undefined;
  if(action==='dispatch-run'){
    // Internal: started detached by the StopFailure hook; runs only a pending DETACHED claim, once.
    if(!o.handoff_id||!o.session)throw Error('DISPATCH_ID_AND_SESSION_REQUIRED');
    await runDetachedDispatch({manifestPath,storeDir,handoffId:o.handoff_id,sessionId:o.session});
  }else if(action==='status'){
    // Read-only: why automatic handoff would or would not run right now.
    const s=automaticHandoffStatus({manifestPath,storeDir});
    stdout.write(JSON.stringify(s,null,2)+'\n');
    process.exitCode=s.ready?0:2;
  }else if(action==='approve'){
    const a=readActivationManifest(manifestPath);
    stdout.write(JSON.stringify({worktree:a.worktree,task:a.manifest.task,permissions:a.manifest.permissions,budget:a.manifest.budget},null,2)+'\n');
    await confirm('APPROVE '+a.digest.slice(0,8));
    const result=authorizeActivation({manifestPath,storeDir,ownerApproved:true});
    stdout.write(JSON.stringify({state:'APPROVED',...result})+'\n');
  }else if(action==='recover'){
    if(!o.handoff_id||!o.reason)throw Error('RECOVERY_ID_AND_REASON_REQUIRED');
    stdout.write('Verify Codex and every other writer have stopped before reconciling this worktree.\n');
    await confirm('RECONCILE '+o.handoff_id.slice(0,8));
    stdout.write(JSON.stringify(reconcileAutomaticLease({manifestPath,storeDir,handoffId:o.handoff_id,
      ownerVerifiedNoWriter:true,reason:o.reason}))+'\n');
  }else{
    if(o.handoff_id||o.reason||o.session)throw Error('INVALID_HOOK_OPTION');
    // detach: the StopFailure hook returns after validation; Codex runs in a detached runner.
    const result=await handleClaudeHook({event:await hookInput(),manifestPath,storeDir,detach:true});
    stdout.write(JSON.stringify(result)+'\n');
  }
}
main().catch(e=>{const error=e?.message||'HANDOFF_ERROR';
  console.error(JSON.stringify({state:'BLOCKED',error,category:categorizeHandoffError(error),hint:'node automatic-handoff-cli.mjs status --manifest <activation.json>'}));process.exitCode=1;});
