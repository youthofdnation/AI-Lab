/** Owner-selected long-lived read policy. No shell, mailbox write, or path wildcard. */
import {createHash} from 'node:crypto';

export const READ_POLICY_MAIL_KINDS=Object.freeze([
  'mail.status','mail.sync','mail.search','mail.recent','mail.review_pending','mail.read'
]);
export const READ_POLICY_DURATIONS=Object.freeze({day:86400,week:7*86400,month:30*86400,until_revoked:null});
const fp=account=>createHash('sha256').update('rian-mail-account-v2|'+account).digest('hex');

export function planReadPolicy({account,accountType,features,duration,maxSyncDays=14,maxSyncMessages=1000}){
  if(typeof account!=='string'||account.length>320||/[^\x21-\x7e]/.test(account)||
      !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(account))throw Error('INVALID_ACCOUNT');
  if(!['outlook','proton'].includes(accountType))throw Error('INVALID_ACCOUNT_TYPE');
  if(!Array.isArray(features)||features.length===0||features.length>READ_POLICY_MAIL_KINDS.length||
      new Set(features).size!==features.length||features.some(x=>!READ_POLICY_MAIL_KINDS.includes(x)))throw Error('INVALID_READ_FEATURES');
  if(!Object.hasOwn(READ_POLICY_DURATIONS,duration))throw Error('INVALID_POLICY_DURATION');
  if(!Number.isInteger(maxSyncDays)||maxSyncDays<1||maxSyncDays>14||
      !Number.isInteger(maxSyncMessages)||maxSyncMessages<1||maxSyncMessages>1000)throw Error('INVALID_POLICY_SCOPE');
  const normalized=account.toLowerCase();
  return Object.freeze({account:normalized,accountType,accountFp:fp(normalized),
    features:Object.freeze([...features].sort()),duration,seconds:READ_POLICY_DURATIONS[duration],
    maxSyncDays,maxSyncMessages});
}

export function readPolicyAllows(policy,kind,params,{searched=false}={}){
  if(!policy||policy.state!=='ACTIVE'||!policy.features.includes(kind))return false;
  if(kind==='mail.sync')return Number.isInteger(params.days)&&params.days>=1&&params.days<=policy.maxSyncDays&&
    Number.isInteger(params.maxMessages)&&params.maxMessages>=1&&params.maxMessages<=policy.maxSyncMessages;
  if(kind==='mail.read')return searched===true;
  if(kind==='mail.recent'||kind==='mail.review_pending')return Number.isInteger(params.days)&&params.days>=1&&params.days<=policy.maxSyncDays;
  return kind==='mail.status'||kind==='mail.search';
}
