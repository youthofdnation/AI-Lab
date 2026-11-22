/**
 * Threshold rules and the incident engine. Rules describe observations only; they never assign
 * a cause. An incident is notified exactly once when it opens and once when it resolves.
 */
import {INTERVAL_SECONDS,validateSample} from './health-core.mjs';

export const INCIDENT_LABELS=Object.freeze({CPU_HIGH:'CPU 과부하',RAM_HIGH:'RAM 부족',DISK_LOW:'디스크 부족',SERVICE_DOWN:'서비스 중단',OFFLINE:'장치 연결 끊김'});
const MAX_GAP=2*INTERVAL_SECONDS+60; // a missing sample breaks a "sustained" run

function sustained(samples,read,limit,minutes){
  let i=samples.length-1,peak=null;
  const v0=read(samples[i]);
  if(v0==null||v0<limit)return null;
  let first=samples[i];
  for(;i>=0;i--){
    const v=read(samples[i]);
    if(v==null||v<limit)break;
    if(i<samples.length-1&&samples[i+1].ts-samples[i].ts>MAX_GAP)break;
    first=samples[i];peak=Math.max(peak??v,v);
  }
  return samples[samples.length-1].ts-first.ts>=minutes*60?{peak,since:first.ts}:null;
}

/** Pure: active conditions for the newest sample of an ascending window. */
export function evaluate(window,t){
  const out=[];
  if(!window.length)return out;
  const last=window[window.length-1];
  const cpu=sustained(window,s=>s.cpu?.percent,t.cpuPercent,t.cpuMinutes);
  if(cpu)out.push({type:'CPU_HIGH',key:'cpu',label:'CPU',value:cpu.peak,since:cpu.since});
  const ram=sustained(window,s=>s.memory?.percent,t.ramPercent,t.ramMinutes);
  if(ram)out.push({type:'RAM_HIGH',key:'ram',label:'RAM',value:ram.peak,since:ram.since});
  for(const d of last.disks)if(d.percent>=t.diskPercent)out.push({type:'DISK_LOW',key:'disk:'+d.mount,label:d.mount,value:d.percent,since:last.ts});
  const n=Math.max(1,Math.round(t.serviceMisses)),recent=window.slice(-n);
  if(recent.length===n)for(const s of last.services){
    const down=recent.every(x=>x.services.some(y=>y.name===s.name&&y.type===s.type&&y.running===false));
    if(down)out.push({type:'SERVICE_DOWN',key:'svc:'+s.type+':'+s.name,label:s.name,value:null,since:recent[0].ts});
  }
  return out;
}

export class IncidentEngine{
  constructor({directory,store,notifier,clock=()=>Date.now()}){
    this.directory=directory;this.store=store;this.notifier=notifier;this.clock=clock;
  }
  now(){return Math.floor(this.clock()/1000);}
  #event(tenant,device,incidentId,event,info,ts){this.notifier?.enqueue(tenant,device,incidentId,event,info,ts);}

  /** Collector ingest. Returns only {ok,stored}: nothing in the reply can steer a collector. */
  ingest(actor,body){
    if(actor?.kind!=='collector')throw Error('NOT_FOUND');
    const now=this.now(),sample=validateSample(body,actor,now),tenant=actor.tenantId,device=actor.deviceId;
    const result=this.store.transaction(()=>{
      const prev=this.store.lastSeen(tenant,device);
      const stored=this.store.insertSample(tenant,device,sample);
      // Late resends (older than the newest stored sample) are kept as history but do not move incidents.
      if(stored&&(prev==null||sample.ts>=prev))this.#reconcile(tenant,device,sample.ts);
      return {ok:true,stored};
    });
    this.notifier?.deliverSoon();
    return result;
  }
  #reconcile(tenant,device,ts){
    const t=this.directory.tenant(tenant).thresholds;
    const span=Math.max(t.cpuMinutes,t.ramMinutes)*60+Math.ceil(t.serviceMisses)*INTERVAL_SECONDS+2*INTERVAL_SECONDS;
    const window=this.store.samples(tenant,device,ts-span,ts);
    const active=evaluate(window,t);
    const open=this.store.openIncidents(tenant,device);
    const byKey=new Map(open.map(i=>[i.type+'|'+i.keyId,i]));
    const seen=new Set();
    for(const c of active){
      const k=c.type+'|'+this.store.lookup(tenant,c.key);seen.add(k);
      const existing=byKey.get(k);
      if(existing){this.store.touchIncident(existing.id,ts,c.value);continue;}   // ongoing: no new notification
      const id=this.store.openIncident(tenant,device,c.type,c.key,c.label,ts,c.value);
      this.#event(tenant,device,id,'OPENED',{type:c.type,label:c.label,value:c.value,since:c.since},ts);
    }
    for(const i of open){
      const k=i.type+'|'+i.keyId;
      if(i.type==='OFFLINE'||!seen.has(k)){
        if(this.store.resolveIncident(i.id,ts))this.#event(tenant,device,i.id,'RESOLVED',{type:i.type,label:i.label,value:i.peak,since:i.openedAt},ts);
      }
    }
  }
  /** Periodic: devices that stopped reporting. Devices that never reported are reported as "not collected", not as incidents. */
  sweep(){
    const now=this.now();
    let opened=0;
    this.store.transaction(()=>{
      for(const d of this.directory.allDevices()){
        const t=this.directory.tenant(d.tenantId).thresholds,last=this.store.lastSeen(d.tenantId,d.id);
        if(last==null||now-last<t.offlineMinutes*60)continue;
        if(this.store.openIncidents(d.tenantId,d.id).some(i=>i.type==='OFFLINE'))continue;
        const id=this.store.openIncident(d.tenantId,d.id,'OFFLINE','offline','연결',now,Math.round((now-last)/60));
        this.#event(d.tenantId,d.id,id,'OPENED',{type:'OFFLINE',label:'연결',value:null,since:last},now);opened++;
      }
    });
    this.notifier?.deliverSoon();
    return opened;
  }
}
