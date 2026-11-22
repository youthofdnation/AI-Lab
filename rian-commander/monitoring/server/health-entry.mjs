/**
 * RIAN Commander Health service entry point.
 *   RIAN_HEALTH_DB_PATH          SQLite file (persistent volume in production)
 *   RIAN_HEALTH_MASTER_KEY       64 hex chars; tenant keys are derived from it (HKDF)
 *   RIAN_HEALTH_DIRECTORY_JSON   {tenants,devices,principals} with token SHA-256 only
 *   PORT                         listen port
 *   RIAN_HEALTH_LOOPBACK=1       bind 127.0.0.1 (tests); otherwise 0.0.0.0 behind the platform's HTTPS
 *   RIAN_HEALTH_SYNTHETIC=1      label every report as synthetic validation data
 * No AI provider is configured here: reports use the rule-based summary.
 */
import {createServer} from 'node:http';
import {HealthDirectory,TenantVault} from './health-core.mjs';
import {HealthStore} from './health-store.mjs';
import {IncidentEngine} from './health-alerts.mjs';
import {Notifier} from './health-notify.mjs';
import {createHealthHandler} from './health-http.mjs';

const env=process.env;
const directory=new HealthDirectory(JSON.parse(env.RIAN_HEALTH_DIRECTORY_JSON||'null')??{});
const store=new HealthStore({filename:env.RIAN_HEALTH_DB_PATH||'',vault:new TenantVault(env.RIAN_HEALTH_MASTER_KEY||'')});
const log=x=>console.warn(x);
const notifier=new Notifier({directory,store,log});
const engine=new IncidentEngine({directory,store,notifier});
const handler=createHealthHandler({directory,store,engine,synthetic:env.RIAN_HEALTH_SYNTHETIC==='1'});
const port=Number(env.PORT||3000);
if(!Number.isInteger(port)||port<1||port>65535)throw Error('INVALID_PORT');

const server=createServer(async(req,res)=>{
  const chunks=[];let size=0;
  try{
    for await(const c of req){size+=c.byteLength;if(size>64*1024){res.writeHead(413);res.end();return;}chunks.push(c);}
    const headers=new Headers();for(const [k,v] of Object.entries(req.headers))if(typeof v==='string')headers.set(k,v);
    const b=Buffer.concat(chunks);
    const r=await handler(new Request('http://health.internal'+(req.url||'/'),{method:req.method,headers,...(b.length?{body:b}:{})}));
    res.writeHead(r.status,Object.fromEntries(r.headers.entries()));res.end(Buffer.from(await r.arrayBuffer()));
  }catch{if(!res.headersSent){res.writeHead(400,{'content-type':'application/json'});res.end('{"error":"INVALID_REQUEST"}');}}
});
const sweep=setInterval(()=>{try{engine.sweep();}catch{log('RIAN_HEALTH_SWEEP_FAILED');}},60000);
const purge=setInterval(()=>{try{store.purge(Math.floor(Date.now()/1000));}catch{log('RIAN_HEALTH_PURGE_FAILED');}},6*3600*1000);
sweep.unref();purge.unref();
server.listen(port,env.RIAN_HEALTH_LOOPBACK==='1'?'127.0.0.1':'0.0.0.0',()=>console.log('RIAN_HEALTH_READY',port));
const stop=()=>server.close(()=>{store.close();process.exit(0);});
process.once('SIGINT',stop);process.once('SIGTERM',stop);
