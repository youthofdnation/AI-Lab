/**
 * Deterministic 30-day SYNTHETIC scenario (September 2026, KST) for two tenants.
 * Samples go through the real IncidentEngine (validation, rules, incidents, outbox), so the
 * report is produced by the same code path as live data. Never present this as real operations.
 *   node synthetic-30d.mjs <out-dir>   -> report-A.json/.pdf, report-B.json/.pdf
 */
import {mkdtempSync,writeFileSync,mkdirSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {HealthDirectory,TenantVault,sha256Hex,newToken,INTERVAL_SECONDS} from '../server/health-core.mjs';
import {HealthStore} from '../server/health-store.mjs';
import {IncidentEngine} from '../server/health-alerts.mjs';
import {Notifier} from '../server/health-notify.mjs';
import {buildReport} from '../server/health-report.mjs';
import {renderReportPdf} from '../server/health-pdf.mjs';

export const MONTH='2026-09';
export const START=Date.UTC(2026,8,1)/1000-9*3600;   // 2026-09-01 00:00 KST
export const DAYS=30;
const at=(day,h,m=0)=>START+(day-1)*86400+h*3600+m*60;

/** What the scenario contains, so tests can compare the report with ground truth. */
export const EXPECTED={
  A:{CPU_HIGH:1,RAM_HIGH:1,DISK_LOW:1,SERVICE_DOWN:1,OFFLINE:1,open:1},
  B:{CPU_HIGH:0,RAM_HIGH:0,DISK_LOW:0,SERVICE_DOWN:0,OFFLINE:1,open:0}};

function rng(seed){return()=>{seed|=0;seed=seed+0x6D2B79F5|0;let t=Math.imul(seed^seed>>>15,1|seed);t=t+Math.imul(t^t>>>7,61|t)^t;return((t^t>>>14)>>>0)/4294967296;};}

export function syntheticDirectory(){
  const tokens={};const tok=k=>(tokens[k]=newToken());
  const devices=[{id:'A-WEB-01',tenantId:'A',label:'A 웹서버 01'},{id:'A-DB-01',tenantId:'A',label:'A DB서버 01'},{id:'B-OFFICE-01',tenantId:'B',label:'B 행정실 PC'}];
  const principals=[{id:'oa',tenantId:'A',kind:'owner',tokenSha256:sha256Hex(tok('oa'))},{id:'ob',tenantId:'B',kind:'owner',tokenSha256:sha256Hex(tok('ob'))},
    ...devices.map(d=>({id:'c-'+d.id,tenantId:d.tenantId,kind:'collector',deviceId:d.id,tokenSha256:sha256Hex(tok('c-'+d.id))}))];
  const directory=new HealthDirectory({tenants:[{id:'A',name:'합성 고객 A (중소기업 전산실)'},{id:'B',name:'합성 고객 B (학교 행정실)'}],devices,principals});
  return {directory,tokens,devices};
}

function sampleFor(device,ts,r,day,h,m){
  const base={'A-WEB-01':{os:['Linux','Ubuntu 24.04 LTS','x86_64'],cpu:28,ram:58,disk:62,svc:'nginx'},
    'A-DB-01':{os:['Windows','10.0.22631','AMD64'],cpu:35,ram:66,disk:70,svc:'MSSQLSERVER'},
    'B-OFFICE-01':{os:['macOS','26.7.3','arm64'],cpu:12,ram:48,disk:41,svc:'ScreenSharing'}}[device];
  const daily=Math.sin((h+m/60-6)/24*2*Math.PI)*0.5+0.5;      // busier in the afternoon
  let cpu=base.cpu+daily*22+r()*8,ram=base.ram+daily*6+r()*4,disk=base.disk+day*0.12+r()*0.2,running=true;
  const errors=[];
  if(device==='A-DB-01')disk=70+day*0.45;                     // steady growth to ~82 % by day 26
  if(device==='A-DB-01'&&day>=27)disk=86.5+(day-27)*0.3;       // above the 85 % disk rule from day 27, still open at month end
  if(device==='A-WEB-01'&&day===8&&h===14&&m<=20)cpu=95+r()*2;   // 20-minute CPU spike -> CPU_HIGH
  if(device==='A-WEB-01'&&day===12&&h===9&&m===0)cpu=97;        // single 5-minute spike -> no incident
  if(device==='A-DB-01'&&day===15&&h===3&&m<=25)ram=93+r();     // 25 minutes RAM >= 90 % -> RAM_HIGH
  if(device==='A-WEB-01'&&day===20&&h===10&&m<=10)running=false; // 3 samples down -> SERVICE_DOWN
  if(device==='A-WEB-01'&&day===22&&h===16&&m===0)running=false; // single miss -> no incident
  if(device==='B-OFFICE-01'&&day===9&&h===11&&m<=10)errors.push('CPU_UNAVAILABLE');
  const total={'A-WEB-01':16,'A-DB-01':32,'B-OFFICE-01':16}[device]*2**30,diskTotal=500*2**30;
  const pct=v=>Math.round(Math.min(100,Math.max(0,v))*10)/10;
  const d=pct(disk);
  return {deviceId:device,collectedAt:ts,collector:'synthetic',os:{family:base.os[0],version:base.os[1],arch:base.os[2]},
    cpu:errors.length?null:{percent:pct(cpu)},memory:{totalBytes:total,usedBytes:Math.round(total*pct(ram)/100),percent:pct(ram)},
    disks:[{mount:device.startsWith('A-DB')?'C:\\':'/',totalBytes:diskTotal,usedBytes:Math.round(diskTotal*d/100),freeBytes:diskTotal-Math.round(diskTotal*d/100),percent:d}],
    services:[{name:base.svc,type:device.startsWith('A-DB')?'service':'process',running}],collection:{ok:!errors.length,errors}};
}
function offline(device,day,h,m){
  return (device==='A-WEB-01'&&day===18&&h===2&&m<40)||(device==='B-OFFICE-01'&&day===5&&h===12&&m<25);
}

/** Feeds 30 days through the engine. Returns the store/directory and the clock used. */
export function generate({filename,masterKeyHex=randomBytes(32).toString('hex')}){
  const {directory,tokens,devices}=syntheticDirectory();
  const store=new HealthStore({filename,vault:new TenantVault(masterKeyHex)});
  let now=START*1000;
  const notifier=new Notifier({directory,store,autoDeliver:false});
  const engine=new IncidentEngine({directory,store,notifier,clock:()=>now});
  const r=rng(20260901);
  const actors=Object.fromEntries(devices.map(d=>[d.id,directory.authenticate('Bearer '+tokens['c-'+d.id])]));
  for(let ts=START;ts<START+DAYS*86400;ts+=INTERVAL_SECONDS){
    const rel=ts-START,day=Math.floor(rel/86400)+1,h=Math.floor(rel%86400/3600),m=Math.floor(rel%3600/60);
    now=ts*1000;
    for(const d of devices)if(!offline(d.id,day,h,m))engine.ingest(actors[d.id],sampleFor(d.id,ts,r,day,h,m));
    engine.sweep();
  }
  now=(START+DAYS*86400)*1000;   // report "generated" right after the month
  return {store,directory,tokens,engine,notifier,clock:()=>now,reportNow:START+DAYS*86400};
}

if(process.argv[1]===fileURLToPath(import.meta.url)){
  const out=process.argv[2]||'synthetic-out';mkdirSync(out,{recursive:true});
  const dir=mkdtempSync(join(tmpdir(),'rian-health-syn-'));
  const g=generate({filename:join(dir,'health.db')});
  for(const t of ['A','B']){
    const report=await buildReport({store:g.store,directory:g.directory,tenantId:t,month:MONTH,synthetic:true,now:g.reportNow});
    writeFileSync(join(out,`report-${t}.json`),JSON.stringify(report,null,1));
    writeFileSync(join(out,`report-${t}.pdf`),renderReportPdf(report));
    console.log(t,JSON.stringify({incidents:report.facts.incidentCounts,open:report.facts.openIncidents,rate:report.facts.collectionRate,summary:report.summary.source}));
  }
  g.store.close();rmSync(dir,{recursive:true,force:true});
}
