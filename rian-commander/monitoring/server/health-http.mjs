/**
 * /v1/health API (Fetch Request -> Response).
 *   POST /v1/health/ingest                         collector only; reply {ok,stored}
 *   GET  /v1/health/devices                        owner: own devices, latest values, open incidents
 *   GET  /v1/health/devices/<id>/metrics?hours=24  owner: samples (max 168 h)
 *   GET  /v1/health/incidents?days=31              owner
 *   GET  /v1/health/reports/monthly/<YYYY-MM>.json|.pdf   owner
 * Another tenant's device or data answers NOT_FOUND, never "forbidden".
 */
import {ID} from './health-core.mjs';
import {buildReport} from './health-report.mjs';
import {renderReportPdf} from './health-pdf.mjs';

const LIMIT=32*1024;
const json=(v,status=200)=>new Response(JSON.stringify(v),{status,headers:{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'}});

async function body(request){
  const reader=request.body?.getReader();if(!reader)return null;
  const chunks=[];let size=0;
  for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>LIMIT)throw Error('BODY_TOO_LARGE');chunks.push(value);}
  try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw Error('INVALID_JSON');}
}

export function createHealthHandler({directory,store,engine,clock=()=>Date.now(),synthetic=false,aiProvider=null}){
  const nowS=()=>Math.floor(clock()/1000);
  const owner=req=>{let a;try{a=directory.authenticate(req.headers.get('authorization'));}catch{throw Error('UNAUTHENTICATED');}if(a.kind!=='owner')throw Error('NOT_FOUND');return a;};
  const intParam=(url,name,def,min,max)=>{const v=url.searchParams.get(name);if(v==null)return def;const n=Number(v);if(!Number.isInteger(n)||n<min||n>max)throw Error('INVALID_PARAMS');return n;};

  return async function handle(request){
    const url=new URL(request.url),path=url.pathname,method=request.method.toUpperCase();
    try{
      if(method==='GET'&&path==='/health')return json({ok:true,app:'rian-commander-health'});
      if(method==='POST'&&path==='/v1/health/ingest'){
        let actor;try{actor=directory.authenticate(request.headers.get('authorization'));}catch{throw Error('UNAUTHENTICATED');}
        if(actor.kind!=='collector')throw Error('NOT_FOUND');
        return json(engine.ingest(actor,await body(request)));
      }
      if(method!=='GET')return json({error:'NOT_FOUND'},404);
      if(path==='/v1/health/devices'){
        const a=owner(request),now=nowS(),t=directory.tenant(a.tenantId).thresholds;
        const seen=new Map(store.seen(a.tenantId).map(s=>[s.device,s]));
        return json({devices:directory.devicesOf(a.tenantId).map(d=>{
          const s=seen.get(d.id),latest=s?store.samples(a.tenantId,d.id,s.last_seen,s.last_seen)[0]||null:null;
          return {device:d.id,label:d.label,lastSeen:s?.last_seen??null,online:!!s&&now-s.last_seen<t.offlineMinutes*60,
            latest:latest&&{ts:latest.ts,os:latest.os,cpu:latest.cpu,memory:latest.memory,disks:latest.disks,services:latest.services,collection:latest.collection},
            openIncidents:store.openIncidents(a.tenantId,d.id).map(i=>({type:i.type,target:i.label,openedAt:i.openedAt,peak:i.peak}))};
        })});
      }
      let m=/^\/v1\/health\/devices\/([^/]+)\/metrics$/.exec(path);
      if(m){
        const a=owner(request);if(!ID.test(m[1]))throw Error('NOT_FOUND');
        const d=directory.ownedDevice(a,m[1]),hours=intParam(url,'hours',24,1,168),now=nowS();
        return json({device:d.id,samples:store.samples(a.tenantId,d.id,now-hours*3600,now)});
      }
      if(path==='/v1/health/incidents'){
        const a=owner(request),days=intParam(url,'days',31,1,366),now=nowS();
        return json({incidents:store.incidents(a.tenantId,now-days*86400,now).map(i=>({type:i.type,device:i.device,target:i.label,state:i.state,openedAt:i.openedAt,resolvedAt:i.resolvedAt,peak:i.peak}))});
      }
      m=/^\/v1\/health\/reports\/monthly\/(\d{4}-\d{2})\.(json|pdf)$/.exec(path);
      if(m){
        const a=owner(request);
        const report=await buildReport({store,directory,tenantId:a.tenantId,month:m[1],synthetic,aiProvider,now:nowS()});
        if(m[2]==='json')return json(report);
        return new Response(renderReportPdf(report),{headers:{'content-type':'application/pdf','content-disposition':`inline; filename="rian-health-${m[1]}.pdf"`,'cache-control':'no-store','x-content-type-options':'nosniff'}});
      }
      return json({error:'NOT_FOUND'},404);
    }catch(e){
      const code=/^[A-Z][A-Z0-9_]{2,60}$/.test(String(e?.message))?e.message:'INVALID_REQUEST';
      if(code==='UNAUTHENTICATED')return json({error:code},401);
      if(code==='NOT_FOUND')return json({error:code},404);
      if(code==='BODY_TOO_LARGE')return json({error:code},413);
      return json({error:code},400);
    }
  };
}
