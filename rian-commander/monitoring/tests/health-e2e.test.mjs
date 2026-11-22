/**
 * Real processes on this OS: health-entry.mjs (loopback) + the Python collector collecting the
 * machine's real CPU/RAM/disk. Temporary directories and synthetic credentials only.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {createServer} from 'node:net';
import {mkdtempSync,writeFileSync,chmodSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {sha256Hex,newToken} from '../server/health-core.mjs';

const ROOT=fileURLToPath(new URL('..',import.meta.url));
const PYTHON=process.env.PYTHON||(process.platform==='win32'?'python':'python3');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const freePort=()=>new Promise(res=>{const s=createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>res(p));});});

test('real collector -> real health service -> owner API and monthly PDF',{timeout:120000},async t=>{
  const dir=mkdtempSync(join(tmpdir(),'rian-health-e2e-'));
  const port=await freePort(),url='http://127.0.0.1:'+port;
  const tok={owner:newToken(),col:newToken(),other:newToken()};
  const directory={tenants:[{id:'T1',name:'E2E 고객'},{id:'T2',name:'E2E 다른 고객'}],devices:[{id:'E2E-DEV',tenantId:'T1',label:'E2E 장치'},{id:'E2E-OTHER',tenantId:'T2'}],
    principals:[{id:'o1',tenantId:'T1',kind:'owner',tokenSha256:sha256Hex(tok.owner)},{id:'c1',tenantId:'T1',kind:'collector',deviceId:'E2E-DEV',tokenSha256:sha256Hex(tok.col)},
      {id:'o2',tenantId:'T2',kind:'owner',tokenSha256:sha256Hex(tok.other)}]};
  const env={...process.env,PORT:String(port),RIAN_HEALTH_LOOPBACK:'1',RIAN_HEALTH_DB_PATH:join(dir,'h.db'),RIAN_HEALTH_MASTER_KEY:randomBytes(32).toString('hex'),RIAN_HEALTH_DIRECTORY_JSON:JSON.stringify(directory)};
  let server;
  const start=async()=>{server=spawn(process.execPath,[join(ROOT,'server','health-entry.mjs')],{env,stdio:['ignore','pipe','pipe']});let out='';server.stdout.on('data',d=>out+=d);
    for(let i=0;i<100&&!out.includes('RIAN_HEALTH_READY');i++)await sleep(100);assert.match(out,/RIAN_HEALTH_READY/);};
  const stop=async()=>{if(server&&server.exitCode===null){const g=new Promise(r=>server.once('exit',r));server.kill('SIGKILL');await g;}};
  t.after(async()=>{await stop();rmSync(dir,{recursive:true,force:true,maxRetries:5});});
  await start();

  writeFileSync(join(dir,'token'),tok.col);chmodSync(join(dir,'token'),0o600);
  const cfg=(over={})=>{const p=join(dir,'c-'+randomBytes(4).toString('hex')+'.json');writeFileSync(p,JSON.stringify({enabled:true,server_url:url,device_id:'E2E-DEV',token_file:join(dir,'token'),allow_test_loopback:true,
    services:[{name:'definitely-not-running-xyz',type:'process'}],...over}));return p;};
  const collector=p=>spawnSync(PYTHON,[join(ROOT,'collector','rian_health_collector.py'),'once','--config',p],{encoding:'utf8',timeout:60000});
  const owner=async(path,who=tok.owner)=>{const r=await fetch(url+path,{headers:{authorization:'Bearer '+who}});return {status:r.status,body:r.headers.get('content-type')==='application/pdf'?Buffer.from(await r.arrayBuffer()):await r.json()};};

  const disabled=collector(cfg({enabled:false}));
  assert.equal(disabled.status,0);assert.match(disabled.stdout,/COLLECTOR_DISABLED/);
  assert.equal((await owner('/v1/health/devices')).body.devices[0].lastSeen,null,'disabled collector sent nothing');

  const r=collector(cfg());
  assert.equal(r.status,0,r.stdout+r.stderr);
  const dev=(await owner('/v1/health/devices')).body.devices[0];
  assert.equal(dev.online,true);
  assert.ok(dev.latest.memory.percent>0&&dev.latest.disks.length===1);
  assert.equal(dev.latest.services[0].running,false);
  assert.ok(['macOS','Linux','Windows'].includes(dev.latest.os.family));
  assert.deepEqual((await owner('/v1/health/devices',tok.other)).body.devices.map(d=>d.device),['E2E-OTHER'],'other tenant isolated');
  assert.equal((await owner('/v1/health/devices/E2E-DEV/metrics',tok.other)).status,404);

  writeFileSync(join(dir,'bad'),newToken());chmodSync(join(dir,'bad'),0o600);
  const bad=collector(cfg({token_file:join(dir,'bad')}));
  assert.equal(bad.status,3);assert.match(bad.stdout,/SEND_FAILED.*SERVER_HTTP_401/);

  const month=new Date(Date.now()+9*3600*1000).toISOString().slice(0,7);
  const pdf=await owner(`/v1/health/reports/monthly/${month}.pdf`);
  assert.equal(pdf.status,200);assert.ok(pdf.body.toString('latin1').startsWith('%PDF'));

  await stop();
  const down=collector(cfg());
  assert.equal(down.status,3);assert.match(down.stdout,/SEND_FAILED.*SERVER_UNREACHABLE/);
  await start();
  assert.equal((await owner('/v1/health/devices')).body.devices[0].online,true,'data survived a service restart');
});
