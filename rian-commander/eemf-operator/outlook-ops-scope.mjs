/**
 * RIAN Commander proposed Outlook/ECOUNT local-mail operations.
 *
 * SOURCE ONLY. This module DOES NOT execute commands, connect to mail,
 * approve an operation, or grant the agent any file permissions.
 * A durable server-side worker and explicit browser-owner approval are
 * mandatory before these plans can be admitted to a running queue.
 */
import { createHash } from 'node:crypto';

const DEVICE = 'DESKTOP-EEMFO3L';
const CWD = 'Documents/rian-outlook-bridge';
const SCRIPT = 'outlook_bridge.py';
const ID = /^[a-f0-9]{20,64}$/;
const QUERY = /^[^\x00-\x1f\x7f]{1,120}$/;
const allowedNames = new Set(['doctor','search','read','sync']);

function shape(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('INVALID_REQUEST');
  if (Object.keys(value).some(k => !fields.includes(k))) throw Error('UNEXPECTED_FIELD');
}
function intIn(value, low, high) {
  return Number.isInteger(value) && value>=low && value<=high;
}
function noForwarding() { return Object.freeze({ maySend:false, mayDelete:false, mayWriteMailbox:false }); }
export function planOutlookOperation(request) {
  shape(request,['kind','messageId','query','limit','days','maxMessages']);
  const kind=request.kind;
  if (!allowedNames.has(kind)) throw Error('OUTLOOK_OPERATION_NOT_ALLOWED');
  let argv, maxResultBytes, expectedDuration, approval, mode;
  if(kind==='doctor') {
    shape(request,['kind']);
    argv=['python',SCRIPT,'doctor'];
    maxResultBytes=8192;expectedDuration=30;
    approval='SCOPED_METADATA_SESSION';
    mode='SHORT_JOB';
  } else if(kind==='search') {
    shape(request,['kind','query','limit']);
    if(typeof request.query!=='string'||!QUERY.test(request.query)||request.query.trim().length===0||request.query.startsWith('-'))throw Error('INVALID_SEARCH');
    const limit=request.limit===undefined?20:request.limit;
    if(!intIn(limit,1,20))throw Error('INVALID_LIMIT');
    argv=['python',SCRIPT,'search',request.query,'--limit',String(limit)];
    maxResultBytes=32000;expectedDuration=30;
    approval='SCOPED_METADATA_SESSION';
    mode='SHORT_JOB';
  } else if(kind==='read') {
    shape(request,['kind','messageId']);
    if(typeof request.messageId!=='string'||!ID.test(request.messageId))throw Error('INVALID_MESSAGE_ID');
    argv=['python',SCRIPT,'read',request.messageId];
    maxResultBytes=65536;expectedDuration=30;
    approval='EXACT_MESSAGE_ONE_TIME_OWNER_APPROVAL';
    mode='SHORT_JOB';
  } else {
    shape(request,['kind','days','maxMessages']);
    const days=request.days, maxMessages=request.maxMessages;
    if(!intIn(days,1,14)||!intIn(maxMessages,1,1000))throw Error('SYNC_SCOPE_EXCEEDED');
    argv=['python',SCRIPT,'sync','--days',String(days),'--max-messages',String(maxMessages)];
    maxResultBytes=8192;expectedDuration=900;
    approval='EXACT_SYNC_ONE_TIME_OWNER_APPROVAL';
    mode='DURABLE_BACKGROUND_JOB_REQUIRED';
  }
  // No caller-selected working directory, executable, shell, output file, or
  // redirect. The browser owner must approve this exact argv/target/scope.
  const approvalDigest=createHash('sha256')
    .update(JSON.stringify({device:DEVICE,cwd:CWD,argv,approval,mode}))
    .digest('hex');
  return Object.freeze({
    version:'rian-outlook-operation-v1',
    device:DEVICE,
    command:Object.freeze({argv:Object.freeze(argv),cwd:CWD,timeout:mode==='SHORT_JOB'?30:null}),
    approval,
    approvalDigest,
    mode,
    readOnlyMailbox:true, // sync modifies only the local cache, not the mailbox.
    localCacheWrite:kind==='sync'||kind==='search',
    maxResultBytes,
    maximumApprovedRuntimeSeconds:expectedDuration,
    ...noForwarding(),
    mustNotRunViaLegacySynchronousRelay:mode==='DURABLE_BACKGROUND_JOB_REQUIRED',
    ownerApprovalCompleted:false,
    runnable:false
  });
}
