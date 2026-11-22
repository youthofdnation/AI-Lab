import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {mkdtempSync,rmSync,readFileSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomBytes} from 'node:crypto';
import {HealthDirectory,TenantVault,validateSample,sha256Hex,newToken,DEFAULT_THRESHOLDS} from '../server/health-core.mjs';
import {HealthStore} from '../server/health-store.mjs';
import {IncidentEngine,evaluate} from '../server/health-alerts.mjs';
import {Notifier,composeIncidentEmail} from '../server/health-notify.mjs';
import {buildReport,buildMonthlyFacts,guardAiSummary,ruleSummary,monthRange} from '../server/health-report.mjs';
import {renderReportPdf} from '../server/health-pdf.mjs';
import {createHealthHandler} from '../server/health-http.mjs';
import {generate,EXPECTED,MONTH,START} from '../tools/synthetic-30d.mjs';

const tmp=t=>{const d=mkdtempSync(join(tmpdir(),'rian-health-'));t.after(()=>rmSync(d,{recursive:true,force:true}));return d;};
const CAUSE_WORDS=/(원인은|때문|누수|고장|결함|해킹|악성|바이러스|과열|버그|오작동|공격)/;
// "원인은 확인되지 않았습니다" is the required neutral statement, not a cause.
const CAUSE={test:s=>CAUSE_WORDS.test(s.replace(/원인[은이]?\s*확인되지\s*않[^.\n]*/g,''))};

function small(t,{email}={}){
  const tok={oa:newToken(),ob:newToken(),ca:newToken(),cb:newToken()};
  const directory=new HealthDirectory({tenants:[{id:'A',name:'고객 A',...(email?{email}:{})},{id:'B',name:'고객 B'}],
    devices:[{id:'pcA',tenantId:'A',label:'A PC'},{id:'pcB',tenantId:'B',label:'B PC'}],
    principals:[{id:'oa',tenantId:'A',kind:'owner',tokenSha256:sha256Hex(tok.oa)},{id:'ob',tenantId:'B',kind:'owner',tokenSha256:sha256Hex(tok.ob)},
      {id:'ca',tenantId:'A',kind:'collector',deviceId:'pcA',tokenSha256:sha256Hex(tok.ca)},{id:'cb',tenantId:'B',kind:'collector',deviceId:'pcB',tokenSha256:sha256Hex(tok.cb)}]});
  const store=new HealthStore({filename:join(tmp(t),'h.db'),vault:new TenantVault(randomBytes(32).toString('hex'))});
  t.after(()=>store.close());
  let now=1790000000*1000;
  const notifier=new Notifier({directory,store,autoDeliver:false});
  const engine=new IncidentEngine({directory,store,notifier,clock:()=>now});
  const handler=createHealthHandler({directory,store,engine,clock:()=>now});
  const actor=k=>directory.authenticate('Bearer '+tok[k]);
  const sample=(dev,over={})=>({deviceId:dev,collectedAt:Math.floor(now/1000),os:{family:'Linux',version:'test',arch:'x86_64'},cpu:{percent:20},
    memory:{totalBytes:1000,usedBytes:500,percent:50},disks:[{mount:'/srv/secret-data',totalBytes:1000,usedBytes:500,freeBytes:500,percent:50}],
    services:[{name:'nginx-private',type:'process',running:true}],collection:{ok:true,errors:[]},...over});
  const req=(who,path,init={})=>handler(new Request('http://h.test'+path,{...init,headers:{authorization:'Bearer '+tok[who],'content-type':'application/json',...(init.headers||{})}}));
  return {directory,store,engine,notifier,handler,tok,actor,sample,req,step:s=>{now+=s*1000;},now:()=>Math.floor(now/1000)};
}

test('credentials: collectors only ingest for their device; owners only read their tenant',async t=>{
  const f=small(t);
  assert.equal((await f.req('ca','/v1/health/devices')).status,404,'collector cannot read');
  assert.equal((await f.req('oa','/v1/health/ingest',{method:'POST',body:JSON.stringify(f.sample('pcA'))})).status,404,'owner cannot ingest');
  const bad=await f.handler(new Request('http://h.test/v1/health/devices',{headers:{authorization:'Bearer '+'x'.repeat(50)}}));
  assert.equal(bad.status,401);
  const other=await f.req('ca','/v1/health/ingest',{method:'POST',body:JSON.stringify(f.sample('pcB'))});
  assert.deepEqual(await other.json(),{error:'DEVICE_MISMATCH'});
  const ok=await f.req('ca','/v1/health/ingest',{method:'POST',body:JSON.stringify(f.sample('pcA'))});
  assert.deepEqual(Object.keys(await ok.json()).sort(),['ok','stored'],'reply carries no instruction');
  assert.equal((await f.req('ob','/v1/health/devices/pcA/metrics')).status,404,'tenant B cannot see A metrics');
  assert.equal((await f.req('oa','/v1/health/devices/pcA/metrics')).status,200);
  const month=new Date((f.now()+9*3600)*1000).toISOString().slice(0,7);
  const bReport=JSON.stringify(await (await f.req('ob',`/v1/health/reports/monthly/${month}.json`)).json());
  assert.ok(bReport.includes('pcB')&&!bReport.includes('pcA')&&!bReport.includes('nginx-private'),'B report is B-only');
  const bDevices=await (await f.req('ob','/v1/health/devices')).json();
  assert.deepEqual(bDevices.devices.map(d=>d.device),['pcB']);
});

test('sample validation: bounds, clock skew, duplicates, unknown fields dropped',t=>{
  const f=small(t),a=f.actor('ca'),now=f.now();
  assert.throws(()=>validateSample({...f.sample('pcA'),collectedAt:now-3600},a,now),/CLOCK_SKEW/);
  assert.throws(()=>validateSample(f.sample('pcA',{cpu:{percent:140}}),a,now),/INVALID_SAMPLE/);
  assert.throws(()=>validateSample(f.sample('pcA',{services:[{name:'rm -rf /;',type:'process',running:false}]}),a,now),/INVALID_SAMPLE/);
  assert.throws(()=>validateSample(f.sample('pcA',{disks:Array(17).fill({mount:'/',totalBytes:1,usedBytes:1,freeBytes:0,percent:100})}),a,now),/INVALID_SAMPLE/);
  const v=validateSample({...f.sample('pcA'),command:'reboot',script:'x'},a,now);
  assert.equal('command' in v||'script' in v,false);
  assert.deepEqual(f.engine.ingest(a,f.sample('pcA')),{ok:true,stored:true});
  assert.deepEqual(f.engine.ingest(a,f.sample('pcA')),{ok:true,stored:false},'resend of the same timestamp is idempotent');
});

test('storage: per-tenant encryption, no plaintext labels in the database',t=>{
  const f=small(t);
  f.engine.ingest(f.actor('ca'),f.sample('pcA'));
  const dbFile=f.store.db.prepare('PRAGMA database_list').get().file;
  f.store.db.exec('PRAGMA wal_checkpoint(FULL)');
  const raw=readFileSync(dbFile).toString('latin1');
  for(const s of ['nginx-private','secret-data','x86_64'])assert.equal(raw.includes(s),false,'plaintext leaked: '+s);
  const vault=new TenantVault(randomBytes(32).toString('hex'));
  const e=vault.encrypt('A','aad','hello');
  assert.throws(()=>vault.decrypt('B','aad',e),'tenant B key cannot open tenant A data');
  assert.equal(vault.decrypt('A','aad',e).toString(),'hello');
});

test('rules: sustained thresholds, gaps, disk, two consecutive service misses',()=>{
  const t=DEFAULT_THRESHOLDS,s=(ts,cpu,running=true,disk=50)=>({ts,cpu:{percent:cpu},memory:{percent:40},disks:[{mount:'/',percent:disk}],services:[{name:'svc',type:'process',running}]});
  assert.equal(evaluate([s(0,95),s(300,95)],t).length,0,'5 minutes is not 10');
  assert.equal(evaluate([s(0,95),s(300,95),s(600,95)],t)[0].type,'CPU_HIGH');
  assert.equal(evaluate([s(0,95),s(1500,95),s(1800,95)],t).length,0,'a data gap breaks the run');
  assert.equal(evaluate([s(0,20,true,86)],t)[0].type,'DISK_LOW');
  assert.equal(evaluate([s(0,20,true),s(300,20,false)],t).length,0,'one miss is not an incident');
  assert.equal(evaluate([s(0,20,false),s(300,20,false)],t)[0].type,'SERVICE_DOWN');
});

test('30-day synthetic month: incidents match ground truth; one notification per transition',t=>{
  const g=generate({filename:join(tmp(t),'syn.db')});t.after(()=>g.store.close());
  const {from,to}=monthRange(MONTH);
  for(const tenant of ['A','B']){
    const inc=g.store.incidents(tenant,from,to);
    for(const type of ['CPU_HIGH','RAM_HIGH','DISK_LOW','SERVICE_DOWN','OFFLINE'])assert.equal(inc.filter(i=>i.type===type).length,EXPECTED[tenant][type],tenant+' '+type);
    assert.equal(inc.filter(i=>i.state==='OPEN').length,EXPECTED[tenant].open);
    const out=g.store.outbox(tenant);
    assert.equal(out.length,inc.length+inc.filter(i=>i.state==='RESOLVED').length,'exactly one OPENED (+ one RESOLVED) per incident');
    assert.ok(out.every(m=>m.status==='NOT_SENT_DISABLED'),'nothing sent while e-mail is not enabled');
    assert.ok(out.every(m=>/원인: 확인되지 않음/.test(m.message.text)&&!CAUSE.test(m.message.text)));
  }
  const cpu=g.store.incidents('A',from,to).find(i=>i.type==='CPU_HIGH');
  assert.equal(cpu.openedAt,START+7*86400+14*3600+10*60,'opens once 10 minutes are covered');
  assert.equal(cpu.resolvedAt,START+7*86400+14*3600+25*60);
});

test('monthly report: facts, no invented cause, AI text only behind the fact guard',async t=>{
  const g=generate({filename:join(tmp(t),'syn.db')});t.after(()=>g.store.close());
  const base={store:g.store,directory:g.directory,tenantId:'A',month:MONTH,synthetic:true,now:g.reportNow};
  const r=await buildReport(base);
  assert.equal(r.summary.source,'rule');
  assert.equal(r.facts.incidents.length,5);assert.equal(r.facts.collectionRate,99.9,'missing data never rounds up to 100 %');
  assert.ok(r.summary.lines.every(l=>!CAUSE.test(l)));
  assert.ok(r.unconfirmed.some(u=>/원인: 확인되지 않음/.test(u)));
  assert.ok(r.actionItems.some(a=>/미복구: .*디스크 부족/.test(a)));
  const faithful={name:'stub',summarize:async f=>`이번 달 장애 이벤트 ${f.incidents.length}건이 관측됐고 평균 수집 정상률은 ${f.collectionRate}%입니다. 원인은 확인되지 않았습니다.`};
  const ok=await buildReport({...base,aiProvider:faithful});
  assert.equal(ok.summary.source,'ai');
  for(const [name,text,reason] of [
    ['cause','A 웹서버의 CPU 과부하는 메모리 누수 때문입니다.','UNSUPPORTED_CAUSE'],
    ['hardware','디스크 고장으로 서비스가 중단되었습니다.','UNSUPPORTED_CAUSE'],
    ['number','CPU 사용률이 99.4%까지 올랐습니다.','UNSUPPORTED_NUMBER:99.4']]){
    const rr=await buildReport({...base,aiProvider:{name,summarize:async()=>text}});
    assert.equal(rr.summary.source,'rule',name);assert.equal(rr.summary.aiRejected,reason,name);
  }
  const down=await buildReport({...base,aiProvider:{summarize:async()=>{throw Error('AI_UNAVAILABLE');}}});
  assert.equal(down.summary.source,'rule');assert.equal(down.summary.aiRejected,'AI_UNAVAILABLE');
  const slow=await buildReport({...base,aiTimeoutMs:50,aiProvider:{summarize:()=>new Promise(r=>setTimeout(()=>r('늦은 응답'),500))}});
  assert.equal(slow.summary.aiRejected,'AI_TIMEOUT');
  assert.equal(guardAiSummary('원인은 확인되지 않았습니다.',r.facts).ok,true);
});

test('PDF: valid single A4 page with the synthetic label and a consistent xref',async t=>{
  const g=generate({filename:join(tmp(t),'syn.db')});t.after(()=>g.store.close());
  const r=await buildReport({store:g.store,directory:g.directory,tenantId:'A',month:MONTH,synthetic:true,now:g.reportNow});
  const pdf=renderReportPdf(r),s=pdf.toString('latin1');
  assert.ok(s.startsWith('%PDF-1.4'));assert.ok(s.trimEnd().endsWith('%%EOF'));
  assert.equal((s.match(/\/Type \/Page /g)||[]).length,1);
  assert.match(s,/\/MediaBox \[0 0 595 842\]/);
  const hex=w=>[...w].map(c=>c.codePointAt(0).toString(16).padStart(4,'0')).join('');
  assert.ok(s.includes(hex('합성'))&&s.includes(hex('실제 운영 성과가 아닙니다.'.split(' ')[0])),'synthetic label present');
  const xref=Number(/startxref\n(\d+)/.exec(s)[1]);
  assert.equal(s.slice(xref,xref+4),'xref');
  const offsets=[...s.slice(xref).matchAll(/^(\d{10}) 00000 n $/gm)].map(m=>Number(m[1]));
  offsets.forEach((o,i)=>assert.ok(s.startsWith(`${i+1} 0 obj`,o),'object '+(i+1)+' offset'));
  assert.ok(pdf.length<200000);
});

test('e-mail: sent only when enabled, once per transition, bounded retries',async t=>{
  const got=[];let reject=false;
  const server=net.createServer(sock=>{
    sock.write('220 test\r\n');let data=false,buf='';
    sock.on('data',d=>{buf+=d.toString();let i;while((i=buf.indexOf('\r\n'))>=0){const line=buf.slice(0,i);buf=buf.slice(i+2);
      if(data){if(line==='.'){data=false;got[got.length-1].done=true;sock.write('250 ok\r\n');}else got[got.length-1].lines.push(line);continue;}
      if(/^EHLO/.test(line))sock.write('250 hi\r\n');
      else if(/^MAIL FROM/.test(line))sock.write(reject?'550 no\r\n':'250 ok\r\n');
      else if(/^RCPT TO/.test(line))sock.write('250 ok\r\n');
      else if(line==='DATA'){got.push({lines:[]});data=true;sock.write('354 go\r\n');}
      else if(line==='QUIT'){sock.write('221 bye\r\n');sock.end();}}});
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>server.close());
  const email={enabled:true,recipients:['ops@example.test'],from:'rian@example.test',smtp:{host:'127.0.0.1',port:server.address().port,implicitTls:false,allowLoopbackPlain:true}};
  const f=small(t,{email});
  const a=f.actor('ca');
  for(let i=0;i<3;i++){f.engine.ingest(a,f.sample('pcA',{cpu:{percent:96}}));f.step(300);}
  for(let i=0;i<3;i++){f.engine.ingest(a,f.sample('pcA',{cpu:{percent:97}}));f.step(300);}   // ongoing: no new mail
  f.engine.ingest(a,f.sample('pcA',{cpu:{percent:20}}));
  assert.deepEqual(await f.notifier.deliver(),{sent:2,failed:0});
  assert.deepEqual(await f.notifier.deliver(),{sent:0,failed:0},'never re-sent');
  assert.equal(got.length,2);
  const decoded=got.map(m=>{const i=m.lines.indexOf('');const subj=/=\?UTF-8\?B\?([^?]+)\?=/.exec(m.lines.find(l=>l.startsWith('Subject:')))[1];
    return {subject:Buffer.from(subj,'base64').toString(),body:Buffer.from(m.lines.slice(i+1).join(''),'base64').toString()};});
  assert.match(decoded[0].subject,/발생: CPU 과부하/);assert.match(decoded[1].subject,/복구: CPU 과부하/);
  assert.ok(decoded.every(d=>/원인: 확인되지 않음/.test(d.body)&&!CAUSE.test(d.body)));
  reject=true;
  f.step(300);for(let i=0;i<3;i++){f.engine.ingest(a,f.sample('pcA',{cpu:{percent:99}}));f.step(300);}
  for(let i=0;i<5;i++)await f.notifier.deliver();
  const statuses=f.store.outbox('A').map(m=>m.status);
  assert.deepEqual(statuses,['SENT','SENT','GAVE_UP'],'failed delivery stops after 3 attempts');
  assert.equal(f.store.outbox('B').length,0);
});

test('e-mail stays off without explicit enable, recipients, sender and SMTP',()=>{
  const d=new HealthDirectory({tenants:[{id:'A',email:{enabled:true,recipients:[]}}],devices:[],principals:[]});
  assert.equal(d.tenant('A').email.enabled,false);
  assert.throws(()=>new HealthDirectory({tenants:[{id:'A',email:{recipients:['bad address']}}],devices:[],principals:[]}),/INVALID_EMAIL_CONFIG/);
  const m=composeIncidentEmail({tenant:{name:'A',email:{recipients:['a@b.test'],from:'r@b.test'}},deviceLabel:'PC',event:'OPENED',info:{type:'DISK_LOW',label:'/',value:91},ts:1790000000});
  assert.match(m.text,/관측 최고값: 91%/);
});

test('HTTP: devices, metrics, incidents, report JSON and PDF for the owner',async t=>{
  const f=small(t);
  for(let i=0;i<4;i++){f.engine.ingest(f.actor('ca'),f.sample('pcA',{disks:[{mount:'/',totalBytes:100,usedBytes:90,freeBytes:10,percent:90}]}));f.step(300);}
  const dev=await (await f.req('oa','/v1/health/devices')).json();
  assert.equal(dev.devices[0].online,true);assert.equal(dev.devices[0].openIncidents[0].type,'DISK_LOW');
  const met=await (await f.req('oa','/v1/health/devices/pcA/metrics?hours=2')).json();
  assert.equal(met.samples.length,4);
  assert.equal((await f.req('oa','/v1/health/devices/pcA/metrics?hours=999')).status,400);
  const inc=await (await f.req('oa','/v1/health/incidents')).json();
  assert.equal(inc.incidents.length,1);
  const month=new Date((f.now()+9*3600)*1000).toISOString().slice(0,7);
  const pdf=await f.req('oa',`/v1/health/reports/monthly/${month}.pdf`);
  assert.equal(pdf.headers.get('content-type'),'application/pdf');
  assert.ok(Buffer.from(await pdf.arrayBuffer()).toString('latin1').startsWith('%PDF'));
});

test('retention: raw samples after 30 days, history after 12 months',t=>{
  const f=small(t);
  f.engine.ingest(f.actor('ca'),f.sample('pcA'));
  const r=f.store.purge(f.now()+31*86400);
  assert.equal(r.samples,1);
});
