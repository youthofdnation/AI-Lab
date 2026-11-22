/**
 * Monthly inspection report. Facts are computed only from stored samples and incidents.
 * The summary is rule-based by default. An optional AI provider may write it, but its text is
 * used only if it cites no percentage absent from the facts and asserts no unconfirmed cause.
 */
import {INTERVAL_SECONDS} from './health-core.mjs';
import {INCIDENT_LABELS} from './health-alerts.mjs';
import {kst} from './health-notify.mjs';

const r1=v=>v==null?null:Math.round(v*10)/10;
const floor1=v=>v==null?null:Math.floor(v*10)/10;   // rates never round up to 100 % when data is missing
function stats(values){
  const v=values.filter(x=>typeof x==='number').sort((a,b)=>a-b);
  if(!v.length)return null;
  return {avg:r1(v.reduce((s,x)=>s+x,0)/v.length),p95:r1(v[Math.min(v.length-1,Math.ceil(v.length*0.95)-1)]),max:r1(v[v.length-1])};
}

/** KST calendar month 'YYYY-MM' -> [from,to] epoch seconds (inclusive). */
export function monthRange(month){
  const m=/^(\d{4})-(0[1-9]|1[0-2])$/.exec(month||'');
  if(!m)throw Error('INVALID_MONTH');
  const from=Date.UTC(+m[1],+m[2]-1,1)/1000-9*3600,to=Date.UTC(+m[1],+m[2],1)/1000-9*3600-1;
  return {from,to,month};
}

export function buildMonthlyFacts({store,directory,tenantId,from,to,synthetic=false,generatedAt=Math.floor(Date.now()/1000)}){
  const tenant=directory.tenant(tenantId),t=tenant.thresholds;
  const end=Math.min(to,generatedAt),expectedPerDevice=Math.max(1,Math.floor((end-from+1)/INTERVAL_SECONDS));
  const devices=directory.devicesOf(tenantId).map(d=>{
    const s=store.samples(tenantId,d.id,from,end);
    const ok=s.filter(x=>x.collection.ok).length;
    const gaps=[];
    for(let i=0,prev=from;i<=s.length;i++){
      const ts=i<s.length?s[i].ts:end;
      if(ts-prev>=t.offlineMinutes*60)gaps.push({from:prev,to:ts,minutes:Math.round((ts-prev)/60)});
      prev=ts;
    }
    const disks=new Map();
    for(const x of s)for(const k of x.disks){const e=disks.get(k.mount)||{mount:k.mount,max:0,latest:null};e.max=Math.max(e.max,k.percent);e.latest=k.percent;disks.set(k.mount,e);}
    const services=new Map();
    for(const x of s)for(const v of x.services){const e=services.get(v.name)||{name:v.name,type:v.type,downSamples:0,samples:0};e.samples++;if(v.running===false)e.downSamples++;services.set(v.name,e);}
    const errors=new Map();
    for(const x of s)for(const e of x.collection.errors)errors.set(e,(errors.get(e)||0)+1);
    const last=s[s.length-1];
    return {device:d.id,label:d.label,os:last?.os||null,samples:s.length,okSamples:ok,expected:expectedPerDevice,
      collectionRate:floor1(Math.min(100,100*ok/expectedPerDevice)),cpu:stats(s.map(x=>x.cpu?.percent)),ram:stats(s.map(x=>x.memory?.percent)),
      disks:[...disks.values()].map(e=>({...e,max:r1(e.max),latest:r1(e.latest)})),services:[...services.values()],
      gaps:gaps.slice(0,20),gapCount:gaps.length,gapMinutes:gaps.reduce((a,g)=>a+g.minutes,0),collectionErrors:Object.fromEntries(errors),
      firstSampleAt:s[0]?.ts??null,lastSampleAt:last?.ts??null};
  });
  const labels=new Map(directory.devicesOf(tenantId).map(d=>[d.id,d.label]));
  const incidents=store.incidents(tenantId,from,end).map(i=>({type:i.type,typeLabel:INCIDENT_LABELS[i.type]||i.type,device:i.device,deviceLabel:labels.get(i.device)||i.device,
    target:i.label,openedAt:i.openedAt,resolvedAt:i.resolvedAt,state:i.state,durationMinutes:i.resolvedAt?Math.round((i.resolvedAt-i.openedAt)/60):null,peak:i.peak==null?null:r1(i.peak)}));
  const rates=devices.map(d=>d.collectionRate);
  return {tenant:{id:tenant.id,name:tenant.name},period:{from,to,end},synthetic:!!synthetic,generatedAt,thresholds:{...t},
    deviceCount:devices.length,reportingDevices:devices.filter(d=>d.samples>0).length,
    collectionRate:rates.length?floor1(rates.reduce((a,b)=>a+b,0)/rates.length):null,devices,incidents,
    incidentCounts:Object.fromEntries(Object.keys(INCIDENT_LABELS).map(k=>[k,incidents.filter(i=>i.type===k).length])),
    openIncidents:incidents.filter(i=>i.state==='OPEN').length,
    confirmedCauses:[]}; // the MVP collects no cause evidence (no logs), so no cause is ever confirmed
}

export function ruleSummary(f){
  const out=[];
  out.push(`점검 기간 ${kst(f.period.from).slice(0,10)}~${kst(f.period.end).slice(0,10)} 동안 등록 장치 ${f.deviceCount}대 중 ${f.reportingDevices}대에서 데이터를 수집했고, 평균 수집 정상률은 ${f.collectionRate??0}%입니다.`);
  const counts=Object.entries(f.incidentCounts).filter(([,n])=>n>0).map(([k,n])=>`${INCIDENT_LABELS[k]} ${n}건`);
  out.push(counts.length?`장애 이벤트는 총 ${f.incidents.length}건(${counts.join(', ')})이 관측됐고, `+(f.openIncidents?`이 중 ${f.openIncidents}건이 보고서 작성 시점까지 복구되지 않았습니다.`:'보고서 작성 시점에는 모두 복구된 상태입니다.'):'점검 기간 동안 임계치를 넘은 장애 이벤트는 관측되지 않았습니다.');
  const busiest=[...f.devices].filter(d=>d.cpu).sort((a,b)=>b.cpu.p95-a.cpu.p95)[0];
  if(busiest)out.push(`CPU 사용률 p95가 가장 높은 장치는 ${busiest.label}(${busiest.cpu.p95}%, 최대 ${busiest.cpu.max}%)입니다.`);
  const full=f.devices.flatMap(d=>d.disks.filter(k=>k.latest>=f.thresholds.diskPercent).map(k=>`${d.label} ${k.mount} ${k.latest}%`));
  if(full.length)out.push(`디스크 사용률이 기준(${f.thresholds.diskPercent}%) 이상인 볼륨: ${full.join(', ')}.`);
  if(f.incidents.length)out.push('원인 로그를 수집하지 않으므로 각 이벤트의 원인은 확인되지 않았습니다.');
  return out;
}

export function actionItems(f){
  const items=[];
  for(const i of f.incidents.filter(i=>i.state==='OPEN'))items.push(`미복구: ${i.deviceLabel} ${i.typeLabel}${i.target&&!['CPU','RAM','연결'].includes(i.target)?' ('+i.target+')':''} — ${kst(i.openedAt)}부터 지속`);
  for(const d of f.devices){
    for(const k of d.disks)if(k.latest>=f.thresholds.diskPercent)items.push(`디스크 여유 공간 확보 검토: ${d.label} ${k.mount} (현재 ${k.latest}%)`);
    if(d.samples===0)items.push(`수집기 설치·활성화 확인: ${d.label} (점검 기간 중 수신 없음)`);
    else if(d.collectionRate<95)items.push(`수집 누락 점검: ${d.label} (수집 정상률 ${d.collectionRate}%)`);
    for(const s of d.services)if(s.downSamples>0)items.push(`서비스 중단 이력 확인: ${d.label} ${s.name} (중단 관측 ${s.downSamples}회)`);
  }
  return items;
}

export function unconfirmedItems(f){
  const items=[];
  if(f.incidents.length)items.push(`장애 이벤트 ${f.incidents.length}건의 원인: 확인되지 않음 (원인 근거 데이터 미수집)`);
  for(const d of f.devices){
    if(d.samples===0)items.push(`${d.label}: 점검 기간 데이터 없음`);
    else if(d.gapCount)items.push(`${d.label}: 데이터 미수집 구간 ${d.gapCount}건, 합계 ${d.gapMinutes}분`);
    const errs=Object.entries(d.collectionErrors);
    if(errs.length)items.push(`${d.label}: 수집 오류 ${errs.map(([k,n])=>k+' '+n+'회').join(', ')}`);
  }
  if(f.period.end<f.period.to)items.push(`보고서 작성 시점(${kst(f.period.end)}) 이후 기간은 포함되지 않음`);
  return items;
}

const CAUSE=/(원인은|원인으로|원인이었|때문|누수|고장|결함|해킹|악성|바이러스|과열|버그|오작동|공격|불량)/;
function factPercents(f){
  const s=new Set();
  const add=v=>{if(typeof v==='number'){s.add(r1(v));s.add(Math.round(v));}};
  add(f.collectionRate);Object.values(f.thresholds).forEach(add);
  for(const d of f.devices){add(d.collectionRate);for(const k of ['cpu','ram'])if(d[k])Object.values(d[k]).forEach(add);for(const k of d.disks){add(k.max);add(k.latest);}}
  for(const i of f.incidents)add(i.peak);
  return s;
}

/** Guard for AI text: only observed percentages, no cause unless the facts confirm one. */
export function guardAiSummary(text,f){
  if(typeof text!=='string'||!text.trim())return {ok:false,reason:'EMPTY'};
  if(text.length>1500)return {ok:false,reason:'TOO_LONG'};
  const neutral=text.replace(/원인[은이]?\s*(확인되지\s*않|미확인|불명|알\s*수\s*없)[^.。\n]*/g,'');
  if(!f.confirmedCauses.length&&CAUSE.test(neutral))return {ok:false,reason:'UNSUPPORTED_CAUSE'};
  const allowed=factPercents(f);
  for(const m of text.matchAll(/(\d+(?:\.\d+)?)\s*%/g)){
    const v=Number(m[1]);
    if(!allowed.has(r1(v))&&!allowed.has(Math.round(v)))return {ok:false,reason:'UNSUPPORTED_NUMBER:'+m[1]};
  }
  return {ok:true};
}

export async function buildReport({store,directory,tenantId,month,synthetic=false,aiProvider=null,now=Math.floor(Date.now()/1000),aiTimeoutMs=20000}){
  const {from,to}=monthRange(month);
  const facts=buildMonthlyFacts({store,directory,tenantId,from,to,synthetic,generatedAt:now});
  const rule=ruleSummary(facts);
  let summary={source:'rule',lines:rule};
  if(aiProvider&&typeof aiProvider.summarize==='function'){
    try{
      const text=await Promise.race([aiProvider.summarize(structuredClone(facts)),new Promise((_,rej)=>setTimeout(()=>rej(Error('AI_TIMEOUT')),aiTimeoutMs).unref?.())]);
      const g=guardAiSummary(text,facts);
      summary=g.ok?{source:'ai',provider:String(aiProvider.name||'ai').slice(0,40),lines:text.split(/\n+/).map(s=>s.trim()).filter(Boolean)}
                  :{source:'rule',lines:rule,aiRejected:g.reason};
    }catch(e){summary={source:'rule',lines:rule,aiRejected:String(e?.message||'AI_UNAVAILABLE').slice(0,40)};}
  }
  return {month,facts,summary,actionItems:actionItems(facts),unconfirmed:unconfirmedItems(facts)};
}
