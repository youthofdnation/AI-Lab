import test from 'node:test';
import assert from 'node:assert/strict';
import {planOutlookOperation} from './outlook-ops-scope.mjs';
const id='b6df3aa45a1dd1b8b6f3';

test('doctor and bounded search only use fixed executable/workspace',()=>{
 const doctor=planOutlookOperation({kind:'doctor'});
 assert.deepEqual(doctor.command.argv,['python','outlook_bridge.py','doctor']);
 assert.equal(doctor.command.cwd,'Documents/rian-outlook-bridge');
 const search=planOutlookOperation({kind:'search',query:'이재철',limit:10});
 assert.deepEqual(search.command.argv,['python','outlook_bridge.py','search','이재철','--limit','10']);
 assert.equal(search.approval,'SCOPED_METADATA_SESSION');
 assert.equal(search.runnable,false);
});
test('read is exactly one message with separate one-shot owner approval',()=>{
 const p=planOutlookOperation({kind:'read',messageId:id});
 assert.deepEqual(p.command.argv,['python','outlook_bridge.py','read',id]);
 assert.equal(p.approval,'EXACT_MESSAGE_ONE_TIME_OWNER_APPROVAL');
 assert.equal(p.ownerApprovalCompleted,false);
 assert.equal(p.runnable,false);
 assert.equal(p.localCacheWrite,false);
 assert.equal(p.maySend,false);
 assert.equal(p.mayDelete,false);
});
test('different message IDs produce distinct hashes and cannot be widened',()=>{
 const x=planOutlookOperation({kind:'read',messageId:id});
 const y=planOutlookOperation({kind:'read',messageId:'57a71bbbfc63af2dfe94'});
 assert.notEqual(x.approvalDigest,y.approvalDigest);
 for(const value of ['',id+' --all',id+'\n--all','--all','../../secrets','a'.repeat(500)])
  assert.throws(()=>planOutlookOperation({kind:'read',messageId:value}));
 assert.throws(()=>planOutlookOperation({kind:'read',messageId:id,limit:50}),/UNEXPECTED_FIELD/);
});
test('14-day local sync is explicit and MUST use durable background jobs',()=>{
 const plan=planOutlookOperation({kind:'sync',days:14,maxMessages:1000});
 assert.equal(plan.mode,'DURABLE_BACKGROUND_JOB_REQUIRED');
 assert.equal(plan.mustNotRunViaLegacySynchronousRelay,true);
 assert.deepEqual(plan.command.argv,['python','outlook_bridge.py','sync','--days','14','--max-messages','1000']);
 assert.equal(plan.command.timeout,null);
 assert.equal(plan.localCacheWrite,true);
 assert.equal(plan.readOnlyMailbox,true);
 assert.equal(plan.approval,'EXACT_SYNC_ONE_TIME_OWNER_APPROVAL');
});
test('rejects excess sync scope and any attempted arbitrary shell/arguments',()=>{
 for(const request of [
  {kind:'sync',days:180,maxMessages:3000},
  {kind:'sync',days:0,maxMessages:20},
  {kind:'sync',days:14,maxMessages:1001},
  {kind:'sync',days:14,maxMessages:-1},
  {kind:'send',to:'anyone'},
  {kind:'delete',messageId:id},
  {kind:'read',messageId:id,argv:['powershell','-c','whoami']},
  {kind:'search',query:'--all'},
  {kind:'search',query:'x',limit:99},
  {kind:'search',query:'x\nx'},
  {kind:'doctor',cwd:'../secrets'}
 ]) assert.throws(()=>planOutlookOperation(request));
});
test('no privileged mail operation is executable on the basis of a plan alone',()=>{
 for(const q of [{kind:'read',messageId:id},{kind:'sync',days:14,maxMessages:1000}]){
  const v=planOutlookOperation(q);
  assert.equal(v.runnable,false);
  assert.equal(v.ownerApprovalCompleted,false);
  assert.equal(v.maySend,false);
  assert.equal(v.mayDelete,false);
  assert.equal(v.mayWriteMailbox,false);
 }
});
