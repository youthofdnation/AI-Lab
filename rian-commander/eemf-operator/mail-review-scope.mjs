/**
 * RIAN Commander V2 — owner-approved, read-only mail review session policy.
 *
 * The browser password approves a *device + owner + OAuth-client* scope once.
 * No arbitrary shell, mailbox writes, mail send/delete, or path selection is added.
 * An opted-in message read is allowed only after its id appeared in a successful
 * search within the same session and within the bounded age window.
 */
import {createHash} from 'node:crypto';

export const REVIEW_LIMITS=Object.freeze({
  maxMinutes:60,maxExtraJobs:60,maxBodyReads:20,maxSyncDays:14,maxSyncMessages:1000,maxSearchHits:20
});
export const MAIL_REVIEW_KINDS=Object.freeze(['mail.sync','mail.search','mail.read']);
const HEXID=/^[a-f0-9]{20,64}$/;
const CLIENT=/^[a-f0-9]{16,64}$/;
const within=(v,lower,upper)=>Number.isInteger(v)&&v>=lower&&v<=upper;
export const reviewMessageHash=id=>createHash('sha256').update(String(id)).digest('hex');

/** Refuses implicit body permission and arbitrary mailbox/account requests. */
export function planMailReview({initialKind,initialParams,clientRef,minutes=30,extraJobs=30,bodyReads=0}){
  if(initialKind!=='mail.sync'||!initialParams||!CLIENT.test(clientRef||''))throw Error('MAIL_REVIEW_INITIAL_SYNC_REQUIRED');
  if(!within(initialParams.days,1,REVIEW_LIMITS.maxSyncDays)
    ||!within(initialParams.maxMessages,1,REVIEW_LIMITS.maxSyncMessages))throw Error('MAIL_REVIEW_SCOPE_INVALID');
  if(!within(minutes,1,REVIEW_LIMITS.maxMinutes)||!within(extraJobs,1,REVIEW_LIMITS.maxExtraJobs)
    ||!within(bodyReads,0,REVIEW_LIMITS.maxBodyReads))throw Error('MAIL_REVIEW_SCOPE_INVALID');
  return Object.freeze({minutes,extraJobs,bodyReads,maxDays:initialParams.days,maxMessages:initialParams.maxMessages});
}

/** A read grant does not cover arbitrary message IDs; only prior fresh search hits. */
export function reviewAllows(session,kind,params,readIdWasSearched=false){
  if(!session||session.state!=='ACTIVE'||session.runs_left<=0||!MAIL_REVIEW_KINDS.includes(kind))return false;
  if(kind==='mail.sync')return within(params.days,1,session.max_days)&&within(params.maxMessages,1,session.max_messages);
  if(kind==='mail.search')return typeof params.query==='string'&&within(params.limit,1,REVIEW_LIMITS.maxSearchHits);
  return typeof params.messageId==='string'&&HEXID.test(params.messageId)&&
    session.reads_left>0&&readIdWasSearched===true;
}

/** Return only message digests, never mail body or even a raw message ID. */
export function recentMessageHashes(output,{nowSeconds,maxDays,maxHits=REVIEW_LIMITS.maxSearchHits}){
  if(!output||typeof output!=='object'||output.ok!==true||!Array.isArray(output.results)
    ||!within(maxDays,1,REVIEW_LIMITS.maxSyncDays)||!within(maxHits,1,REVIEW_LIMITS.maxSearchHits)
    ||!Number.isSafeInteger(nowSeconds)||nowSeconds<0)return [];
  const earliest=(nowSeconds-maxDays*86400)*1000,latest=(nowSeconds+300)*1000;
  const hashes=new Set();
  for(const row of output.results.slice(0,maxHits)){
    if(!row||!HEXID.test(row.message_id||'')||typeof row.date!=='string')continue;
    const ts=Date.parse(row.date);
    if(!Number.isFinite(ts)||ts<earliest||ts>latest)continue;
    hashes.add(reviewMessageHash(row.message_id));
  }
  return [...hashes];
}
