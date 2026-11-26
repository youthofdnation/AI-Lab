/** Durable owner sessions and single-use WebAuthn ceremonies for staging. */
import {createHash,randomBytes,randomUUID} from 'node:crypto';

const sha=x=>createHash('sha256').update(x).digest('hex');
const TOKEN=/^[A-Za-z0-9_-]{40,100}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export class OwnerCenterStore {
  #store;#clock;#rpID;
  constructor({store,clock=()=>Date.now(),rpID}){this.#store=store;this.#clock=clock;this.#rpID=rpID;}
  #db(){return this.#store.db;}
  #now(){return Math.floor(this.#clock()/1000);}
  createSession({tenant,owner,method}){
    if(!tenant||!owner||!['password','passkey','google'].includes(method))throw Error('INVALID_OWNER_SESSION');
    const token=randomBytes(32).toString('base64url'),now=this.#now(),digest=sha(token);
    this.#db().prepare('INSERT INTO owner_center_sessions(sha,tenant,owner,method,created,expires) VALUES(?,?,?,?,?,?)')
      .run(digest,tenant,owner,method,now,now+1800);
    this.#store.audit(tenant,owner,digest.slice(0,16),'OWNER_CENTER_LOGIN_'+method.toUpperCase(),now);
    return {token,sha:digest,expires_at:now+1800};
  }
  session(token){
    if(typeof token!=='string'||!TOKEN.test(token))return null;
    const row=this.#db().prepare('SELECT * FROM owner_center_sessions WHERE sha=? AND expires>?').get(sha(token),this.#now());
    return row?{sha:row.sha,tenant:row.tenant,owner:row.owner,method:row.method,expires_at:row.expires,
      actor:{kind:'owner',tenantId:row.tenant,id:row.owner}}:null;
  }
  logout(session){this.#db().prepare('DELETE FROM owner_center_sessions WHERE sha=?').run(session.sha);}
  loginAllowed(key){
    const now=this.#now();
    const row=this.#db().prepare('SELECT count,until FROM owner_login_failures WHERE key=?').get(key);
    const global=this.#db().prepare("SELECT count,until FROM owner_login_failures WHERE key='global'").get();
    return !(row&&row.until>now&&row.count>=5)&&!(global&&global.until>now&&global.count>=100);
  }
  failedLogin(key){
    const now=this.#now();
    for(const k of [key,'global']){
      this.#db().prepare('INSERT INTO owner_login_failures(key,count,until) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN until>? THEN count+1 ELSE 1 END,until=CASE WHEN until>? THEN until ELSE excluded.until END')
        .run(k,now+600,now,now);
    }
  }
  clearLoginFailure(key){this.#db().prepare('DELETE FROM owner_login_failures WHERE key=?').run(key);}
  bindGoogleIdentity({tenant,owner,subject}){
    if(typeof subject!=='string'||subject.length<6||subject.length>256||!tenant||!owner)
      throw Error('INVALID_GOOGLE_IDENTITY');
    const subjectSha=sha('google|'+subject),now=this.#now();
    this.#store.transaction(()=>{
      const prior=this.#db().prepare("SELECT subject_sha FROM owner_identity_bindings WHERE tenant=? AND owner=? AND provider='google'")
        .get(tenant,owner);
      if(prior){if(prior.subject_sha!==subjectSha)throw Error('GOOGLE_IDENTITY_CHANGED');return;}
      this.#db().prepare("INSERT INTO owner_identity_bindings(tenant,owner,provider,subject_sha,created) VALUES(?,?,'google',?,?)")
        .run(tenant,owner,subjectSha,now);
      this.#store.audit(tenant,owner,subjectSha.slice(0,16),'GOOGLE_IDENTITY_BOUND',now);
    });
  }
  createChallenge({kind,challenge,tenant=null,owner=null,sessionSha=null,flowSha=null,requestId=null,scopeHash=null,scopeJson=null}){
    if(!['register','login','approve_policy','approve_job','google_login'].includes(kind)||typeof challenge!=='string'||challenge.length<32)
      throw Error('INVALID_PASSKEY_CHALLENGE');
    const id=randomUUID(),now=this.#now();
    this.#db().prepare('INSERT INTO passkey_challenges(id,kind,challenge,tenant,owner,session_sha,flow_sha,request_id,scope_hash,scope_json,created,expires) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(id,kind,challenge,tenant,owner,sessionSha,flowSha,requestId,scopeHash,scopeJson,now,now+300);
    return {id,expires_at:now+300};
  }
  consumeChallenge({id,kind,tenant=null,owner=null,sessionSha=null,flowSha=null}){
    if(typeof id!=='string'||!UUID.test(id))throw Error('CHALLENGE_NOT_FOUND');
    return this.#store.transaction(()=>{
      const row=this.#db().prepare('SELECT * FROM passkey_challenges WHERE id=?').get(id);
      if(!row||row.kind!==kind||row.expires<=this.#now()||row.used!==0||row.tenant!==tenant||row.owner!==owner||
        row.session_sha!==sessionSha||row.flow_sha!==flowSha)throw Error('CHALLENGE_NOT_FOUND');
      if(this.#db().prepare('UPDATE passkey_challenges SET used=1 WHERE id=? AND used=0').run(id).changes!==1)
        throw Error('CHALLENGE_NOT_FOUND');
      return row;
    });
  }
  credentials(tenant,owner){
    return this.#db().prepare("SELECT * FROM passkey_credentials WHERE tenant=? AND owner=? AND rp_id=? AND status='ACTIVE' ORDER BY created")
      .all(tenant,owner,this.#rpID).map(row=>this.#credential(row));
  }
  credential(id){
    if(typeof id!=='string'||id.length<8||id.length>1024||!/^[A-Za-z0-9_-]+$/.test(id))return null;
    const row=this.#db().prepare("SELECT * FROM passkey_credentials WHERE id=? AND rp_id=? AND status='ACTIVE'").get(id,this.#rpID);
    return row?this.#credential(row):null;
  }
  #credential(row){return {...row,publicKey:new Uint8Array(this.#store.decrypt({cipher:row.public_key_cipher,
    iv:row.public_key_iv,tag:row.public_key_tag},'passkey-public|'+row.tenant+'|'+row.owner+'|'+row.id)),
    transports:JSON.parse(row.transports)};}
  saveCredential({tenant,owner,credential,transports=[]}){
    if(!credential?.id||!(credential.publicKey instanceof Uint8Array)||!Number.isSafeInteger(credential.counter)||credential.counter<0)
      throw Error('INVALID_PASSKEY_CREDENTIAL');
    const enc=this.#store.encrypt(Buffer.from(credential.publicKey),'passkey-public|'+tenant+'|'+owner+'|'+credential.id);
    this.#db().prepare('INSERT INTO passkey_credentials(id,tenant,owner,rp_id,public_key_cipher,public_key_iv,public_key_tag,counter,transports,status,created) VALUES(?,?,?,?,?,?,?,?,?,\'ACTIVE\',?)')
      .run(credential.id,tenant,owner,this.#rpID,enc.cipher,enc.iv,enc.tag,credential.counter,JSON.stringify(transports),this.#now());
    this.#store.audit(tenant,owner,credential.id.slice(0,32),'PASSKEY_REGISTERED',this.#now());
  }
  revokeCredential({tenant,owner,id}){
    const changed=this.#db().prepare("UPDATE passkey_credentials SET status='REVOKED' WHERE id=? AND tenant=? AND owner=? AND rp_id=? AND status='ACTIVE'")
      .run(id,tenant,owner,this.#rpID);
    if(changed.changes!==1)throw Error('PASSKEY_NOT_REGISTERED');
    this.#store.audit(tenant,owner,id.slice(0,32),'PASSKEY_REVOKED',this.#now());
    return {revoked:true};
  }
  advanceCounter(credential,newCounter){
    if(!Number.isSafeInteger(newCounter)||newCounter<0||(credential.counter>0&&newCounter<=credential.counter))
      throw Error('PASSKEY_COUNTER_REPLAY');
    const changed=this.#db().prepare("UPDATE passkey_credentials SET counter=? WHERE id=? AND counter=? AND status='ACTIVE' AND rp_id=?")
      .run(newCounter,credential.id,credential.counter,this.#rpID);
    if(changed.changes!==1)throw Error('PASSKEY_COUNTER_REPLAY');
  }
}
