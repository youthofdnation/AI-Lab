/**
 * Dedicated RIAN Commander STAGING service. Never import into production Relay.
 * Default is a private, health-only instance. Enabling /v2 artifacts or V2
 * long-running jobs requires explicit authenticated two-tenant config.
 */
import {StagingSqlite} from './staging-sqlite.mjs';
import {createStagingService,stagingConfigFromEnv} from './staging-server.mjs';

if(process.env.RIAN_STAGE_ONLY!=='1')throw Error('STAGING_MODE_REQUIRED');
const filename=process.env.RIAN_STAGE_DB_PATH||'';
if(!filename.startsWith('/data/')||filename.includes('..'))throw Error('STAGING_VOLUME_PATH_REQUIRED');
const config=stagingConfigFromEnv(process.env);
const store=new StagingSqlite({filename,encryptionKeyHex:process.env.RIAN_STAGE_STORAGE_KEY||''});
const bootSequence=store.bootSequence();
const {server,recovery,artifactsEnabled,jobsEnabled}=createStagingService({store,config,log:x=>console.warn(x)});
const port=Number(process.env.PORT||3000);
if(!Number.isInteger(port)||port<1||port>65535)throw Error('INVALID_PORT');
server.listen(port,'0.0.0.0',()=>{
  // Only a monotonic boot count and job counters are logged, not any tenant details or secrets.
  console.log('RIAN_STAGING_VOLUME_BOOT_SEQUENCE',bootSequence);
  if(recovery)console.log('RIAN_STAGING_LONG_JOBS_RECOVERED',JSON.stringify(recovery));
  console.log('RIAN_STAGING_READY',artifactsEnabled||jobsEnabled?'AUTHENTICATED_API':'HEALTH_ONLY',jobsEnabled?'LONG_JOBS':'NO_LONG_JOBS');
});
function shutdown(){server.close(()=>{store.close();process.exit(0)});}
process.once('SIGINT',shutdown);
process.once('SIGTERM',shutdown);
