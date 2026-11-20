/**
 * Dedicated RIAN Commander STAGING service. Never import into production Relay.
 * Default is a private, health-only instance. Enabling /v2 requires explicit
 * authenticated two-tenant config and a separate browser approval issuer.
 */
import {createServer} from 'node:http';
import {StagingSqlite} from './staging-sqlite.mjs';
import {TenantDirectory,OwnerTransferApproval} from './tenant-artifact-core.mjs';
import {DurableTenantArtifactBroker} from './durable-tenant-artifacts.mjs';
import {createStagingArtifactHandler} from './tenant-artifact-http.mjs';

if(process.env.RIAN_STAGE_ONLY!=='1')throw Error('STAGING_MODE_REQUIRED');
const filename=process.env.RIAN_STAGE_DB_PATH||'';
if(!filename.startsWith('/data/')||filename.includes('..'))throw Error('STAGING_VOLUME_PATH_REQUIRED');
const store=new StagingSqlite({filename,encryptionKeyHex:process.env.RIAN_STAGE_STORAGE_KEY||''});
const bootSequence=store.bootSequence();
const enabled=process.env.RIAN_STAGE_API_ENABLED==='1';
let handler=null;
if(enabled){
  // These configuration variables must be provisioned only in an isolated
  // staging environment. Never reuse the production global device token map.
  let principals,devices;
  try {
    principals=JSON.parse(process.env.RIAN_STAGE_PRINCIPALS_JSON||'null');
    devices=JSON.parse(process.env.RIAN_STAGE_DEVICES_JSON||'null');
  }catch{throw Error('INVALID_TENANT_CONFIGURATION');}
  if(!Array.isArray(principals)||!Array.isArray(devices)||new Set(principals.map(p=>p.tenantId)).size<2)throw Error('INDEPENDENT_TEST_TENANTS_REQUIRED');
  const directory=new TenantDirectory({principals,devices});
  const approval=new OwnerTransferApproval(process.env.RIAN_STAGE_APPROVAL_SECRET||'');
  const broker=new DurableTenantArtifactBroker({directory,approval,store});
  handler=createStagingArtifactHandler({directory,broker});
}
const port=Number(process.env.PORT||3000);
if(!Number.isInteger(port)||port<1||port>65535)throw Error('INVALID_PORT');
const LIMIT=110000;
const server=createServer(async(req,res)=>{
  res.setHeader('cache-control','no-store');
  res.setHeader('x-content-type-options','nosniff');
  if(req.method==='GET'&&req.url==='/health'){
    res.writeHead(200,{'content-type':'application/json'});
    res.end(JSON.stringify({ok:true,app:'rian-commander-staging',durable:true,apiEnabled:enabled}));
    return;
  }
  if(!enabled||!req.url?.startsWith('/v2/')){
    res.writeHead(404,{'content-type':'application/json'});
    res.end('{"error":"NOT_FOUND"}');return;
  }
  let chunks=[],size=0;
  try {
    for await(const chunk of req){
      size+=chunk.byteLength;
      if(size>LIMIT){res.writeHead(413);res.end();return;}
      chunks.push(chunk);
    }
    const body=Buffer.concat(chunks);
    const headers=new Headers();
    for(const [name,value] of Object.entries(req.headers))if(typeof value==='string')headers.set(name,value);
    const request=new Request('http://staging.internal'+req.url,{method:req.method,headers, ...(body.length?{body}: {})});
    const response=await handler(request);
    res.writeHead(response.status,Object.fromEntries(response.headers.entries()));
    res.end(Buffer.from(await response.arrayBuffer()));
  }catch{
    if(!res.headersSent){res.writeHead(400,{'content-type':'application/json'});res.end('{"error":"INVALID_REQUEST"}');}
  }
});
server.listen(port,'0.0.0.0',()=>{
  // Only a monotonic boot count is logged, not any tenant details or secrets.
  console.log('RIAN_STAGING_VOLUME_BOOT_SEQUENCE',bootSequence);
  console.log('RIAN_STAGING_READY',enabled?'AUTHENTICATED_API':'HEALTH_ONLY');
});
function shutdown(){server.close(()=>{store.close();process.exit(0)});}
process.once('SIGINT',shutdown);
process.once('SIGTERM',shutdown);
