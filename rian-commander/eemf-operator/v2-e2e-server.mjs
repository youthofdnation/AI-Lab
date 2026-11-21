/**
 * TEST-ONLY launcher: runs the real staging service (same createStagingService
 * as staging-entry.mjs) on 127.0.0.1 with a temporary SQLite file so the
 * Windows/Linux E2E can kill and restart it. Not copied into the Docker image.
 */
import {StagingSqlite} from './staging-sqlite.mjs';
import {createStagingService,stagingConfigFromEnv} from './staging-server.mjs';

if(process.env.RIAN_V2_E2E!=='1')throw Error('E2E_ONLY');
const port=Number(process.env.PORT);
if(!Number.isInteger(port)||port<1024)throw Error('INVALID_PORT');
const config=stagingConfigFromEnv(process.env);
if(config.publicOrigin!=='http://127.0.0.1:'+port)throw Error('LOOPBACK_ORIGIN_REQUIRED');
const store=new StagingSqlite({filename:process.env.RIAN_E2E_DB_PATH,encryptionKeyHex:process.env.RIAN_STAGE_STORAGE_KEY||''});
const boot=store.bootSequence();
const {server,recovery}=createStagingService({store,config});
server.listen(port,'127.0.0.1',()=>{
  console.log('RIAN_STAGING_VOLUME_BOOT_SEQUENCE',boot);
  console.log('RIAN_STAGING_LONG_JOBS_RECOVERED',JSON.stringify(recovery));
  console.log('RIAN_V2_E2E_READY',port);
});
