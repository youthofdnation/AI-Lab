#!/usr/bin/env node
/**
 * Owner-operated approval/recovery and Claude command-hook entry point.
 *   P2.2 project grant (Issue #9, recommended):
 *     grant  --worktree ABS [--runs 5] [--days 7] [--run-minutes 20] [--read-only]   one owner click (native dialog)
 *     revoke --worktree ABS                     immediate, no confirmation needed
 *     status --worktree ABS                     read-only readiness
 *     hook-grant                                Claude command hook (grant looked up from the event's cwd)
 *   P2 manifest mode (per-task seal): approve | hook | recover | status --manifest ABS
 */
import {stdin,stdout} from 'node:process';
import {createInterface} from 'node:readline/promises';
import {resolve} from 'node:path';
import {authorizeActivation,automaticHandoffStatus,categorizeHandoffError,createProjectGrant,grantHandoffStatus,handleClaudeHook,
  readActivationManifest,reconcileAutomaticLease,revokeProjectGrant,runDetachedDispatch} from './automatic-handoff.mjs';
import {confirmGrantByDialog,grantSummary} from './handoff-grant.mjs';

const VALUE=['--manifest','--worktree','--store','--handoff-id','--reason','--session','--runs','--days','--run-minutes'];
const FLAG=['--read-only'];
function args(argv){
  const out={};
  for(let i=0;i<argv.length;i++){
    const k=argv[i],name=k?.slice(2).replaceAll('-','_');
    if(FLAG.includes(k)){if(out[name])throw Error('INVALID_OPTION');out[name]=true;continue;}
    if(!VALUE.includes(k)||!argv[i+1]||out[name]!==undefined)throw Error('INVALID_OPTION');
    out[name]=argv[++i];
  }
  return out;
}
const int=(v,d)=>v===undefined?d:/^\d+$/.test(v)?Number(v):NaN;
async function confirm(phrase){
  if(!stdin.isTTY||!stdout.isTTY)throw Error('INTERACTIVE_OWNER_TERMINAL_REQUIRED');
  const rl=createInterface({input:stdin,output:stdout});
  try{if((await rl.question('Type '+phrase+': ')).trim()!==phrase)throw Error('OWNER_APPROVAL_NOT_GIVEN');}
  finally{rl.close();}
}
/** The owner's own decision: a click in a native dialog (macOS/Windows), else a typed terminal phrase. */
async function confirmGrant(plan){
  stdout.write(grantSummary(plan).join('\n')+'\n');
  if(process.platform==='darwin'||process.platform==='win32'){
    stdout.write('Waiting for the owner to click 승인 or 거절 in the RIAN Commander dialog...\n');
    if(confirmGrantByDialog(plan)!=='APPROVED')throw Error('OWNER_APPROVAL_NOT_GIVEN');
    return process.platform==='darwin'?'macos-dialog':'windows-dialog';
  }
  await confirm('GRANT '+plan.grantId.slice(0,8));
  return 'terminal';
}
async function hookInput(){
  let data='';
  for await(const chunk of stdin){data+=chunk;if(data.length>64_000)throw Error('HOOK_INPUT_TOO_LARGE');}
  return JSON.parse(data);
}
async function main(){
  const [action,...rest]=process.argv.slice(2),o=args(rest);
  const storeDir=o.store?resolve(o.store):undefined;
  const worktree=o.worktree?resolve(o.worktree):undefined,manifestPath=o.manifest?resolve(o.manifest):undefined;
  const grantActions=['grant','revoke','hook-grant'];
  if(![...grantActions,'approve','hook','recover','status','dispatch-run'].includes(action)||
    (['grant','revoke'].includes(action)&&!worktree)||
    (['approve','hook','recover'].includes(action)&&!manifestPath)||
    (['status','dispatch-run'].includes(action)&&!worktree===!manifestPath))
    throw Error('USAGE: grant|revoke|status --worktree ABS | hook-grant | approve|hook|recover|status --manifest ABS');
  if(action==='grant'){
    const g=await createProjectGrant({worktree,storeDir,runs:int(o.runs,5),days:int(o.days,7),runMinutes:int(o.run_minutes,20),
      workspaceWrite:!o.read_only,confirm:confirmGrant});
    stdout.write(JSON.stringify({state:'GRANTED',grantId:g.grantId,worktree:g.worktree,expiresAt:g.expiresAt,maxRuns:g.maxRuns,approvedVia:g.approvedVia})+'\n');
  }else if(action==='revoke'){
    stdout.write(JSON.stringify(revokeProjectGrant({worktree,storeDir,reason:o.reason}))+'\n');
  }else if(action==='hook-grant'){
    if(Object.keys(o).some(k=>k!=='store'))throw Error('INVALID_HOOK_OPTION');
    // detach: the StopFailure hook returns after validation; Codex runs in a detached runner.
    const result=await handleClaudeHook({event:await hookInput(),grant:true,storeDir,detach:true});
    stdout.write(JSON.stringify(result)+'\n');
  }else if(action==='dispatch-run'){
    // Internal: started detached by the StopFailure hook; runs only a pending DETACHED claim, once.
    if(!o.handoff_id||!o.session)throw Error('DISPATCH_ID_AND_SESSION_REQUIRED');
    await runDetachedDispatch({manifestPath,grantWorktree:worktree,storeDir,handoffId:o.handoff_id,sessionId:o.session});
  }else if(action==='status'){
    // Read-only: why automatic handoff would or would not run right now.
    const s=worktree?grantHandoffStatus({worktree,storeDir}):automaticHandoffStatus({manifestPath,storeDir});
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
    const result=await handleClaudeHook({event:await hookInput(),manifestPath,storeDir,detach:true});
    stdout.write(JSON.stringify(result)+'\n');
  }
}
main().catch(e=>{const error=e?.message||'HANDOFF_ERROR';
  console.error(JSON.stringify({state:'BLOCKED',error,category:categorizeHandoffError(error),hint:'node automatic-handoff-cli.mjs status --worktree <ABS> (or --manifest <activation.json>)'}));process.exitCode=1;});
