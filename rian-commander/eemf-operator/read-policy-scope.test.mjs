import test from 'node:test';
import assert from 'node:assert/strict';
import {planReadPolicy,readPolicyAllows} from './read-policy-scope.mjs';

test('owner selects explicit account, provider, duration and read features',()=>{
 const p=planReadPolicy({account:'Owner@Example.Test',accountType:'outlook',duration:'month',
   features:['mail.search','mail.status','mail.sync']});
 assert.equal(p.account,'owner@example.test');assert.match(p.accountFp,/^[a-f0-9]{64}$/);
 assert.equal(p.seconds,30*86400);
 assert.equal(readPolicyAllows({...p,state:'ACTIVE'},'mail.sync',{days:14,maxMessages:1000}),true);
 assert.equal(readPolicyAllows({...p,state:'ACTIVE'},'mail.read',{messageId:'a'.repeat(40)},{searched:true}),false);
 assert.equal(readPolicyAllows({...p,state:'REVOKED'},'mail.status',{}),false);
});

test('mail bodies require explicit feature and search; dangerous kinds never enter policy',()=>{
 const p=planReadPolicy({account:'owner@example.test',accountType:'proton',duration:'until_revoked',features:['mail.search','mail.read']});
 assert.equal(p.seconds,null);
 assert.equal(readPolicyAllows({...p,state:'ACTIVE'},'mail.read',{},{}),false);
 assert.equal(readPolicyAllows({...p,state:'ACTIVE'},'mail.read',{}, {searched:true}),true);
 for(const kind of ['mail.send','mail.delete','shell.exec'])
   assert.throws(()=>planReadPolicy({account:'owner@example.test',accountType:'proton',duration:'day',features:[kind]}),/INVALID_READ_FEATURES/);
 assert.throws(()=>planReadPolicy({account:'owner@example.test',accountType:'outlook',duration:'day',features:['mail.search','mail.search']}),/INVALID_READ_FEATURES/);
});
