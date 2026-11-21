/**
 * Cross-language integration: REAL HTTP over localhost between the Python
 * source/destination agents and the authenticated Node durable broker.
 * Synthetic files/tenants only. No production devices or public endpoints.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {TenantDirectory,OwnerTransferApproval} from './tenant-artifact-core.mjs';
import {StagingSqlite} from './staging-sqlite.mjs';
import {DurableTenantArtifactBroker} from './durable-tenant-artifacts.mjs';
import {createStagingArtifactHandler} from './tenant-artifact-http.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const PYTHON=fileURLToPath(new URL('./tenant-artifact-agent.py',import.meta.url));
// Windows has no real `python3` (only a Store alias stub); honour PYTHON for CI matrices.
const PYTHON_EXE=process.env.PYTHON||(process.platform==='win32'?'python':'python3');
const PY_SCRIPT=String.raw`
import importlib.util,json,sys
spec=importlib.util.spec_from_file_location("rian_agent",sys.argv[1])
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
client=mod.Client(sys.argv[2],sys.argv[3],allow_test_loopback=True)
if sys.argv[4]=="upload":
    result=mod.upload(client,sys.argv[5],"result.bin",sys.argv[6])
else:
    result=mod.download(client,sys.argv[5],sys.argv[6])
print(json.dumps(result))
`;

function runPython(args){
 return new Promise((resolve,reject)=>{
   const p=spawn(PYTHON_EXE,['-c',PY_SCRIPT,PYTHON,...args],{stdio:['ignore','pipe','pipe']});
   let stdout='',stderr='';
   p.stdout.on('data',x=>stdout+=x.toString('utf8'));
   p.stderr.on('data',x=>stderr+=x.toString('utf8'));
   p.on('error',reject);
   p.on('close',code=>code===0?resolve(JSON.parse(stdout)):reject(Error('PYTHON_AGENT_FAILED '+code+' '+stderr.slice(0,400))));
 });
}

test('real HTTP / Python source+target across two tenants with durable encrypted broker',async t=>{
 const temp=mkdtempSync(join(tmpdir(),'rian-crosslang-')),src=join(temp,'source'),dst=join(temp,'inbox');
 mkdirSync(src);mkdirSync(dst);
 const bytes=randomBytes(65536+1024),fingerprint=sha(bytes);
 writeFileSync(join(src,'result.bin'),bytes);
 const tokens=Object.fromEntries(['ownerA','ownerB','srcA','dstA','srcB','dstB'].map(id=>[id,randomBytes(48).toString('base64url')]));
 const dirs=[{id:'pc-A-source',tenantId:'A'},{id:'pc-A-dest',tenantId:'A'},
             {id:'pc-B-source',tenantId:'B'},{id:'pc-B-dest',tenantId:'B'}];
 const principals=[
  ['ownerA','A','owner'],['srcA','A','agent','pc-A-source'],['dstA','A','agent','pc-A-dest'],
  ['ownerB','B','owner'],['srcB','B','agent','pc-B-source'],['dstB','B','agent','pc-B-dest'],
 ].map(([id,tenantId,kind,deviceId])=>({id,tenantId,kind,...(deviceId?{deviceId}:{}),tokenSha256:sha(tokens[id])}));
 const directory=new TenantDirectory({principals,devices:dirs});
 const signer=new OwnerTransferApproval(randomBytes(48).toString('hex'));
 const aesKey=randomBytes(32).toString('hex'),dbPath=join(temp,'durable.sqlite');
 let store=new StagingSqlite({filename:dbPath,encryptionKeyHex:aesKey});
 const createBroker=()=>new DurableTenantArtifactBroker({directory,approval:signer,store});
 let broker=createBroker(),handler=createStagingArtifactHandler({directory,broker});
 const server=createServer(async(req,res)=>{
   try{
     const chunks=[];for await(const x of req)chunks.push(x);
     const body=Buffer.concat(chunks),headers={};
     for(const [k,v] of Object.entries(req.headers))if(typeof v==='string')headers[k]=v;
     const request=new Request('http://127.0.0.1'+req.url,{method:req.method,headers,...(body.length?{body}:{})});
     const response=await handler(request);
     res.writeHead(response.status,Object.fromEntries(response.headers.entries()));
     res.end(Buffer.from(await response.arrayBuffer()));
   }catch{res.writeHead(400);res.end();}
 });
 t.after(async()=>{await new Promise(resolve=>server.close(resolve));store.close();rmSync(temp,{recursive:true,force:true});});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const host='http://127.0.0.1:'+server.address().port, now=Math.floor(Date.now()/1000);
 const proof=signer.issue({tenantId:'A',ownerId:'ownerA',sourceDeviceId:'pc-A-source',targetDeviceId:'pc-A-dest',
   sizeBytes:bytes.length,sha256:fingerprint,expiresAt:now+120,nonce:randomBytes(16).toString('hex')});
 const r=await fetch(host+'/v2/transfers',{method:'POST',headers:{authorization:'Bearer '+tokens.ownerA,'content-type':'application/json'},
  body:JSON.stringify({sourceDeviceId:'pc-A-source',targetDeviceId:'pc-A-dest',name:'result.bin',
    sizeBytes:bytes.length,sha256:fingerprint,approvalProof:proof,idempotencyKey:randomBytes(24).toString('base64url')})});
 assert.equal(r.status,201);
 const transferId=(await r.json()).transferId;
 assert.ok(transferId);
 const alien=await fetch(host+'/v2/transfers/'+transferId,{headers:{authorization:'Bearer '+tokens.ownerB}});
 assert.equal(alien.status,404);
 const outsider=await fetch(host+'/v2/transfers/'+transferId,{headers:{authorization:'Bearer '+tokens.srcB}});
 assert.equal(outsider.status,404);
 const sent=await runPython([host,tokens.srcA,'upload',src,transferId]);
 assert.equal(sent.state,'READY');
 const arrived=await runPython([host,tokens.dstA,'download',dst,transferId]);
 assert.equal(arrived.state,'DELIVERED');
 assert.equal(sha(readFileSync(join(dst,'result.bin'))),fingerprint);
 // Full transaction log, including delivery, remains after database reopen.
 store.close();
 store=new StagingSqlite({filename:dbPath,encryptionKeyHex:aesKey});
 broker=createBroker();handler=createStagingArtifactHandler({directory,broker});
 const ownerA=directory.authenticate('Bearer '+tokens.ownerA);
 assert.equal(broker.status(ownerA,transferId).state,'DELIVERED');
 assert.equal(broker.status(ownerA,transferId).uploadedChunks,0);
 assert.throws(()=>broker.status(directory.authenticate('Bearer '+tokens.ownerB),transferId),/NOT_FOUND_OR_EXPIRED/);
});
