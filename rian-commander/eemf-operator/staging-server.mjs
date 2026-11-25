/**
 * Composes the isolated staging service: health, the existing artifact API and
 * the V2 long-running job API. Shared by staging-entry.mjs (Railway volume) and
 * by local/CI end-to-end tests (temporary directories, loopback only).
 * Never import into the legacy production Relay.
 */
import {createServer} from 'node:http';
import {StagingSqlite} from './staging-sqlite.mjs';
import {TenantDirectory,OwnerTransferApproval} from './tenant-artifact-core.mjs';
import {DurableTenantArtifactBroker} from './durable-tenant-artifacts.mjs';
import {createStagingArtifactHandler} from './tenant-artifact-http.mjs';
import {LongJobQueue} from './durable-long-jobs.mjs';
import {LongJobKinds} from './long-job-kinds.mjs';
import {createLongJobHandler} from './long-job-http.mjs';

const LIMIT=110000;
function parseJson(text,label){
  try{return JSON.parse(text||'null');}catch{throw Error('INVALID_'+label);}
}
/** Reads only explicit configuration; there is no global admin token fallback. */
export function stagingConfigFromEnv(env){
  const artifactsEnabled=env.RIAN_STAGE_API_ENABLED==='1',jobsEnabled=env.RIAN_STAGE_JOBS_ENABLED==='1';
  const cfg={artifactsEnabled,jobsEnabled,allowDiagnostics:env.RIAN_STAGE_ALLOW_DIAGNOSTICS==='1',allowMailReviewTools:env.RIAN_STAGE_MAIL_REVIEW_TOOLS==='1'};
  if(artifactsEnabled||jobsEnabled){
    cfg.principals=parseJson(env.RIAN_STAGE_PRINCIPALS_JSON,'TENANT_CONFIGURATION');
    cfg.devices=parseJson(env.RIAN_STAGE_DEVICES_JSON,'TENANT_CONFIGURATION');
    if(!Array.isArray(cfg.principals)||!Array.isArray(cfg.devices)||new Set(cfg.principals.map(p=>p.tenantId)).size<2)throw Error('INDEPENDENT_TEST_TENANTS_REQUIRED');
  }
  if(artifactsEnabled)cfg.artifactApprovalSecret=env.RIAN_STAGE_APPROVAL_SECRET||'';
  if(jobsEnabled){
    cfg.approvers=parseJson(env.RIAN_STAGE_APPROVERS_JSON,'APPROVER_CONFIGURATION');
    cfg.publicOrigin=(env.RIAN_STAGE_PUBLIC_URL||'').replace(/\/+$/,'');
    cfg.formSecret=env.RIAN_STAGE_FORM_SECRET||'';
  }
  return cfg;
}

export function createStagingService({store,config,clock=()=>Date.now(),log=()=>{}}){
  if(!(store instanceof StagingSqlite))throw Error('INVALID_STORE');
  let artifactHandler=null,jobHandler=null,jobs=null,directory=null;
  if(config.artifactsEnabled||config.jobsEnabled)directory=new TenantDirectory({principals:config.principals,devices:config.devices});
  if(config.artifactsEnabled){
    const approval=new OwnerTransferApproval(config.artifactApprovalSecret);
    artifactHandler=createStagingArtifactHandler({directory,broker:new DurableTenantArtifactBroker({directory,approval,store,clock})});
  }
  let recovery=null;
  if(config.jobsEnabled){
    // Optional per-device allowlist: RIAN_STAGE_DEVICES_JSON [{id,tenantId,allowedKinds:["diag.wait"]}]
    const deviceKinds=new Map((config.devices||[]).filter(d=>d&&d.allowedKinds!==undefined).map(d=>[d.id,d.allowedKinds]));
    jobs=new LongJobQueue({directory,store,kinds:new LongJobKinds({allowDiagnostics:config.allowDiagnostics===true,allowMailReviewTools:config.allowMailReviewTools===true}),clock,deviceKinds});
    recovery=jobs.recoverAfterRestart();
    jobHandler=createLongJobHandler({directory,queue:jobs,approvers:config.approvers,publicOrigin:config.publicOrigin,formSecret:config.formSecret,clock});
  }
  const reaper=jobs?setInterval(()=>{try{jobs.reap();store.sweep(Math.floor(clock()/1000));}catch{log('RIAN_STAGING_REAP_FAILED');}},5000):null;
  reaper?.unref?.();
  const server=createServer(async(req,res)=>{
    res.setHeader('cache-control','no-store');
    res.setHeader('x-content-type-options','nosniff');
    if(req.method==='GET'&&req.url==='/health'){
      res.writeHead(200,{'content-type':'application/json'});
      res.end(JSON.stringify({ok:true,app:'rian-commander-staging',durable:true,apiEnabled:!!artifactHandler,jobsEnabled:!!jobHandler}));
      return;
    }
    const url=req.url||'';
    const target=url.startsWith('/v2/mcp')||url.startsWith('/v2/agent/')||url.startsWith('/v2/approve/')?jobHandler:url.startsWith('/v2/')?artifactHandler:null;
    if(!target){res.writeHead(404,{'content-type':'application/json'});res.end('{"error":"NOT_FOUND"}');return;}
    const chunks=[];let size=0;
    try{
      for await(const chunk of req){size+=chunk.byteLength;if(size>LIMIT){res.writeHead(413);res.end();return;}chunks.push(chunk);}
      const body=Buffer.concat(chunks),headers=new Headers();
      for(const [name,value] of Object.entries(req.headers))if(typeof value==='string')headers.set(name,value);
      const request=new Request('http://staging.internal'+url,{method:req.method,headers,...(body.length?{body}:{})});
      const response=await target(request);
      res.writeHead(response.status,Object.fromEntries(response.headers.entries()));
      res.end(Buffer.from(await response.arrayBuffer()));
    }catch{
      if(!res.headersSent){res.writeHead(400,{'content-type':'application/json'});res.end('{"error":"INVALID_REQUEST"}');}
    }
  });
  server.on('close',()=>{if(reaper)clearInterval(reaper);});
  return {server,jobs,recovery,artifactsEnabled:!!artifactHandler,jobsEnabled:!!jobHandler};
}
